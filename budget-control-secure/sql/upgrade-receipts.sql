-- Executar uma única vez no SQL Editor do projeto Supabase existente.
-- Mantém as despesas e os utilizadores atuais.
ALTER TABLE public.expenses ADD COLUMN IF NOT EXISTS receipt_data bytea;
ALTER TABLE public.expenses ADD COLUMN IF NOT EXISTS receipt_mime text;
