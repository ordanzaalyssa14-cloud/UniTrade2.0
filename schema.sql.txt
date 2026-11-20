-- =====================================
-- UNITRADE DATABASE
-- =====================================

-- 1. STUDENT PROFILES

CREATE TABLE public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL DEFAULT 'Student',
    role TEXT NOT NULL DEFAULT 'student'
        CHECK (role IN ('student', 'admin')),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. PRODUCTS

CREATE TABLE public.products (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    seller_id UUID NOT NULL
        REFERENCES public.profiles(id) ON DELETE CASCADE,

    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price NUMERIC(10,2) NOT NULL CHECK (price > 0),

    category TEXT NOT NULL CHECK (
        category IN (
            'Books',
            'School Supplies',
            'Electronics',
            'Clothing',
            'Other'
        )
    ),

    image_url TEXT,

    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'removed')),

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. ENABLE SECURITY

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.products ENABLE ROW LEVEL SECURITY;

-- 4. PROFILE POLICIES (AUTHENTICATED ONLY)

DROP POLICY IF EXISTS "Authenticated users can view profiles" ON public.profiles;
CREATE POLICY "Authenticated users can view profiles"
ON public.profiles
FOR SELECT TO authenticated
USING (auth.uid() IS NOT NULL);

DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
CREATE POLICY "Users can update own profile"
ON public.profiles
FOR UPDATE TO authenticated
USING (id = (SELECT auth.uid()))
WITH CHECK (
    id = (SELECT auth.uid())
    AND role = (SELECT p.role FROM public.profiles p WHERE p.id = (SELECT auth.uid()))
);

-- 5. PRODUCT POLICIES (AUTHENTICATED ONLY - NO ANON ACCESS)

DROP POLICY IF EXISTS "Public can view active products" ON public.products;
DROP POLICY IF EXISTS "Authenticated users can view active products" ON public.products;
CREATE POLICY "Authenticated users can view active products"
ON public.products
FOR SELECT TO authenticated
USING (
    auth.uid() IS NOT NULL
    AND (
        status = 'active'
        OR seller_id = (SELECT auth.uid())
        OR EXISTS (
            SELECT 1
            FROM public.profiles
            WHERE id = (SELECT auth.uid())
            AND role = 'admin'
        )
    )
);

DROP POLICY IF EXISTS "Students can create products" ON public.products;
CREATE POLICY "Students can create products"
ON public.products
FOR INSERT TO authenticated
WITH CHECK (
    seller_id = (SELECT auth.uid())
    AND EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = (SELECT auth.uid())
    )
);

DROP POLICY IF EXISTS "Sellers and admins can update products" ON public.products;
CREATE POLICY "Sellers and admins can update products"
ON public.products
FOR UPDATE TO authenticated
USING (
    seller_id = (SELECT auth.uid())
    OR EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = (SELECT auth.uid())
        AND role = 'admin'
    )
)
WITH CHECK (
    seller_id = (SELECT auth.uid())
    OR EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = (SELECT auth.uid())
        AND role = 'admin'
    )
);

DROP POLICY IF EXISTS "Sellers and admins can delete products" ON public.products;
CREATE POLICY "Sellers and admins can delete products"
ON public.products
FOR DELETE TO authenticated
USING (
    seller_id = (SELECT auth.uid())
    OR EXISTS (
        SELECT 1 FROM public.profiles
        WHERE id = (SELECT auth.uid())
        AND role = 'admin'
    )
);

-- 5B. ORDERS & CHAT POLICIES (STRICT PARTICIPANT ACCESS, AUTHENTICATED ONLY)

DO $$
BEGIN
    IF to_regclass('public.orders') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY';

        EXECUTE 'DROP POLICY IF EXISTS "Users can view own orders" ON public.orders';
        EXECUTE 'CREATE POLICY "Users can view own orders" ON public.orders FOR SELECT TO authenticated USING (buyer_id = (SELECT auth.uid()) OR seller_id = (SELECT auth.uid()))';

        EXECUTE 'DROP POLICY IF EXISTS "Buyers can create orders" ON public.orders';
        EXECUTE 'CREATE POLICY "Buyers can create orders" ON public.orders FOR INSERT TO authenticated WITH CHECK (buyer_id = (SELECT auth.uid()) AND seller_id <> (SELECT auth.uid()))';

        EXECUTE 'DROP POLICY IF EXISTS "Sellers can update own incoming orders" ON public.orders';
        EXECUTE 'CREATE POLICY "Sellers can update own incoming orders" ON public.orders FOR UPDATE TO authenticated USING (seller_id = (SELECT auth.uid())) WITH CHECK (seller_id = (SELECT auth.uid()))';
    END IF;

    IF to_regclass('public.chat_messages') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY';

        EXECUTE 'DROP POLICY IF EXISTS "Order participants can view chat messages" ON public.chat_messages';
        EXECUTE 'CREATE POLICY "Order participants can view chat messages" ON public.chat_messages FOR SELECT TO authenticated USING (EXISTS (SELECT 1 FROM public.orders o WHERE o.id = order_id AND (o.buyer_id = (SELECT auth.uid()) OR o.seller_id = (SELECT auth.uid()))))';

        EXECUTE 'DROP POLICY IF EXISTS "Order participants can send chat messages" ON public.chat_messages';
        EXECUTE 'CREATE POLICY "Order participants can send chat messages" ON public.chat_messages FOR INSERT TO authenticated WITH CHECK (sender_id = (SELECT auth.uid()) AND EXISTS (SELECT 1 FROM public.orders o WHERE o.id = order_id AND (o.buyer_id = (SELECT auth.uid()) OR o.seller_id = (SELECT auth.uid()))))';

        EXECUTE 'DROP POLICY IF EXISTS "Order participants can mark chat messages read" ON public.chat_messages';
        EXECUTE 'CREATE POLICY "Order participants can mark chat messages read" ON public.chat_messages FOR UPDATE TO authenticated USING (EXISTS (SELECT 1 FROM public.orders o WHERE o.id = order_id AND (o.buyer_id = (SELECT auth.uid()) OR o.seller_id = (SELECT auth.uid()))))';
    END IF;
END $$;

-- 6. AUTOMATIC PROFILE CREATION

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO public.profiles (
        id,
        full_name,
        role
    )
    VALUES (
        NEW.id,
        COALESCE(
            NEW.raw_user_meta_data ->> 'full_name',
            'Student'
        ),
        'student'
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE PROCEDURE public.handle_new_user();