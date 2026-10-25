-- Run once in Supabase SQL Editor before deploying the updated application.
-- Keeps all existing expense rows and receipt data unchanged.
BEGIN;
CREATE TABLE IF NOT EXISTS public.expense_categories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE CHECK (length(trim(name)) BETWEEN 1 AND 80),
  active boolean NOT NULL DEFAULT true,
  sort_order integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
-- Preserve legacy categories for historical expenses; hide them from new entries.
INSERT INTO public.expense_categories(name,active,sort_order)
SELECT name,false,100 FROM (VALUES ('Hardware'),('Serviços'),('Software'),('Outros')) AS v(name)
ON CONFLICT (name) DO NOTHING;
INSERT INTO public.expense_categories(name,active,sort_order)
SELECT name,true,position FROM (VALUES
 ('Days Billed',1),('Hotel',2),('Transport',3),('Flights',4),
 ('Rental Car',5),('Toll',6),('Petrol',7),('Mileage',8),('Others',9)
) AS v(name,position)
ON CONFLICT (name) DO UPDATE SET active=true,sort_order=EXCLUDED.sort_order;
-- Ensure all historical labels are represented, including any custom legacy labels.
INSERT INTO public.expense_categories(name,active,sort_order)
SELECT DISTINCT e.category,false,1000 FROM public.expenses e
WHERE NOT EXISTS (SELECT 1 FROM public.expense_categories c WHERE c.name=e.category)
ON CONFLICT (name) DO NOTHING;
-- The old fixed-list CHECK must be removed so administrator-defined categories can be used.
DO $$ DECLARE constraint_name text; BEGIN
 FOR constraint_name IN
   SELECT conname FROM pg_constraint
   WHERE conrelid='public.expenses'::regclass AND contype='c'
   AND pg_get_constraintdef(oid) ILIKE '%category%'
 LOOP
   EXECUTE format('ALTER TABLE public.expenses DROP CONSTRAINT %I',constraint_name);
 END LOOP;
END $$;
-- One active session per account. Retain the newest valid session when upgrading.
DELETE FROM public.sessions s USING (
  SELECT token_hash, row_number() OVER (PARTITION BY user_id ORDER BY expires_at DESC,token_hash) AS rn
  FROM public.sessions
) d WHERE s.token_hash=d.token_hash AND d.rn>1;
CREATE UNIQUE INDEX IF NOT EXISTS sessions_one_per_user_unique ON public.sessions(user_id);

-- Exact duplicate rule (Option B): same project, owner, title, category,
-- amount, payment method, expense date, receipt MIME and identical receipt bytes.
-- Two missing receipts also compare as identical. Distinct bytes are permitted.
-- The unique index protects concurrent requests as well as create/edit operations.
-- If historical duplicates exist, this statement will fail and roll back the
-- transaction; inspect the preflight query in DEPLOY-INTEGRATED.md first.
CREATE UNIQUE INDEX IF NOT EXISTS expenses_exact_duplicate_unique ON public.expenses
(project_id,owner_id,title,category,amount,method,expense_date,
 (coalesce(md5(receipt_data),'NO_RECEIPT')),
 (coalesce(receipt_mime,'')));
COMMIT;
