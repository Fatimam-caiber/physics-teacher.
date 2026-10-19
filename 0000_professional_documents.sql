CREATE TYPE public.app_role AS ENUM ('admin');

CREATE TABLE public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL,
  UNIQUE (user_id, role)
);
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users read own roles" ON public.user_roles FOR SELECT TO authenticated USING (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role public.app_role)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role)
$$;

CREATE OR REPLACE FUNCTION public.assign_owner_role()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  IF lower(NEW.email) = 'bakirovskaya@gmail.com' AND NEW.email_confirmed_at IS NOT NULL THEN
    INSERT INTO public.user_roles (user_id, role) VALUES (NEW.id, 'admin') ON CONFLICT DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER on_auth_user_owner_role AFTER INSERT OR UPDATE ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.assign_owner_role();

INSERT INTO public.user_roles (user_id, role)
  SELECT id, 'admin' FROM auth.users WHERE lower(email) = 'bakirovskaya@gmail.com' AND email_confirmed_at IS NOT NULL
  ON CONFLICT DO NOTHING;

CREATE TABLE public.professional_documents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  category text NOT NULL CHECK (category IN ('award','development','professional')),
  title_ru text NOT NULL,
  title_ky text NOT NULL,
  description_ru text NOT NULL DEFAULT '',
  description_ky text NOT NULL DEFAULT '',
  doc_date date NOT NULL,
  image_path text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON public.professional_documents TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.professional_documents TO authenticated;
GRANT ALL ON public.professional_documents TO service_role;
ALTER TABLE public.professional_documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anyone can view documents" ON public.professional_documents FOR SELECT TO anon, authenticated USING (true);
CREATE POLICY "Owner inserts documents" ON public.professional_documents FOR INSERT TO authenticated WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Owner updates documents" ON public.professional_documents FOR UPDATE TO authenticated USING (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Owner deletes documents" ON public.professional_documents FOR DELETE TO authenticated USING (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Anyone can view document scans" ON storage.objects FOR SELECT TO anon, authenticated USING (bucket_id = 'professional-documents');
CREATE POLICY "Owner uploads document scans" ON storage.objects FOR INSERT TO authenticated WITH CHECK (bucket_id = 'professional-documents' AND public.has_role(auth.uid(), 'admin'));
CREATE POLICY "Owner deletes document scans" ON storage.objects FOR DELETE TO authenticated USING (bucket_id = 'professional-documents' AND public.has_role(auth.uid(), 'admin'));