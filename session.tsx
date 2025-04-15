'use client';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useRouter } from 'next/navigation';
import { z } from 'zod';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

const formSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
});

export default function LoginPage() {
  const router = useRouter();
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      username: '',
      password: '',
    },
  });

  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(values),
      });

      if (response.ok) {
        router.push('/');
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Invalid credentials');
      }
    } catch (err) {
      setError('Network error - please try again');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow-lg">
        <h2 className="text-3xl font-bold text-center text-gray-900">Sign in</h2>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="mt-8 space-y-6">
            <div className="space-y-4">
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Username</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="Enter your username"
                        {...field}
                        className="focus-visible:ring-blue-500"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input
                        type="password"
                        placeholder="Enter your password"
                        {...field}
                        className="focus-visible:ring-blue-500"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {error && (
              <p className="text-red-500 text-sm text-center">{error}</p>
            )}

            <Button
              type="submit"
              className="w-full bg-blue-600 hover:bg-blue-700 focus-visible:ring-blue-500"
              disabled={loading}
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </Button>
          </form>
        </Form>
      </div>
    </div>
  );
}




Update Middleware (middleware.ts):

typescript
Copy
export async function middleware(request: NextRequest) {
  const { session } = await getSession(request);
  const path = request.nextUrl.pathname;

  // Allow access to login page and public assets
  if (path.startsWith('/login') || path.startsWith('/_next')) {
    return NextResponse.next();
  }

  // Redirect unauthenticated users to login
  if (!session.user) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Existing team authorization logic
  if (path.startsWith('/teams/')) {
    const teamId = path.split('/')[2];
    const result = await db.select()
      .from(teamsTable)
      .where(eq(teamsTable.id, teamId))
      .execute();

    const team = result[0];
    if (!team) return NextResponse.next();

    if (!session.user.groups.includes(team.prcGroup)) {
      return NextResponse.redirect(new URL('/unauthorized', request.url));
    }
  }

  return NextResponse.next();
}
Create Logout API Route (app/api/logout/route.ts):

typescript
Copy
import { NextResponse } from 'next/server';
import { getSession } from '@/lib/session';

export async function POST(request: Request) {
  const { session, res } = await getSession(request);
  session.destroy();
  return new NextResponse(JSON.stringify({ success: true }), {
    status: 200,
    headers: res.headers,
  });
}
Add Navigation Hook (Create hooks/useAuth.ts):

typescript
Copy
'use client';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getSession } from '@/lib/session';

export function useAuth(redirectTo = '/login') {
  const router = useRouter();

  useEffect(() => {
    async function checkAuth() {
      const { session } = await getSession();
      if (!session?.user) {
        router.push(redirectTo);
      }
    }
    
    checkAuth();
  }, [router, redirectTo]);
}
Update Header Component (Example components/Header.tsx):

tsx
Copy
'use client';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

export function Header() {
  const router = useRouter();

  const handleLogout = async () => {
    await fetch('/api/logout', { method: 'POST' });
    router.push('/login');
  };

  return (
    <header className="bg-gray-800 text-white p-4">
      <div className="container mx-auto flex justify-between items-center">
        <Link href="/" className="text-xl font-bold">Your App</Link>
        <button
          onClick={handleLogout}
          className="bg-red-500 hover:bg-red-600 px-4 py-2 rounded"
        >
          Logout
        </button>
      </div>
    </header>
  );
}
Key Features:

Full-stack login flow with error handling

Protected routes via middleware

Session-based authentication

Automatic redirect to login for unauthenticated users

Logout functionality

Reusable auth hook for client-side protection

Responsive login page design

To use in protected pages:

tsx
Copy
// Example protected page
'use client';
import { useAuth } from '@/hooks/useAuth';

export default function ProtectedPage() {
  useAuth(); // Redirects to login if not authenticated
  
  return (
    <div>
      <Header />
      {/* Protected content */}
    </div>
  );
}


'use client';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { useRouter } from 'next/navigation';
import { z } from 'zod';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

const formSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required'),
});

export default function LoginPage() {
  const router = useRouter();
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      username: '',
      password: '',
    },
  });

  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function onSubmit(values: z.infer<typeof formSchema>) {
    setLoading(true);
    setError('');

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(values),
      });

      if (response.ok) {
        router.push('/');
      } else {
        const errorData = await response.json();
        setError(errorData.error || 'Invalid credentials');
      }
    } catch (err) {
      setError('Network error - please try again');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8 p-8 bg-white rounded-lg shadow-lg">
        <h2 className="text-3xl font-bold text-center text-gray-900">Sign in</h2>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="mt-8 space-y-6">
            <div className="space-y-4">
              <FormField
                control={form.control}
                name="username"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Username</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="Enter your username"
                        {...field}
                        className="focus-visible:ring-blue-500"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="password"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Password</FormLabel>
                    <FormControl>
                      <Input
                        type="password"
                        placeholder="Enter your password"
                        {...field}
                        className="focus-visible:ring-blue-500"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {error && (
              <p className="text-red-500 text-sm text-center">{error}</p>
            )}

            <Button
              type="submit"
              className="w-full bg-blue-600 hover:bg-blue-700 focus-visible:ring-blue-500"
              disabled={loading}
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </Button>
          </form>
        </Form>
      </div>
    </div>
  );
}




Update Middleware (middleware.ts):

typescript
Copy
export async function middleware(request: NextRequest) {
  const { session } = await getSession(request);
  const path = request.nextUrl.pathname;

  // Allow access to login page and public assets
  if (path.startsWith('/login') || path.startsWith('/_next')) {
    return NextResponse.next();
  }

  // Redirect unauthenticated users to login
  if (!session.user) {
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Existing team authorization logic
  if (path.startsWith('/teams/')) {
    const teamId = path.split('/')[2];
    const result = await db.select()
      .from(teamsTable)
      .where(eq(teamsTable.id, teamId))
      .execute();

    const team = result[0];
    if (!team) return NextResponse.next();

    if (!session.user.groups.includes(team.prcGroup)) {
      return NextResponse.redirect(new URL('/unauthorized', request.url));
    }
  }

  return NextResponse.next();
}
Create Logout API Route (app/api/logout/route.ts):

typescript
Copy
import { NextResponse } from 'next/server';
import { getSession } from '@/lib/session';

export async function POST(request: Request) {
  const { session, res } = await getSession(request);
  session.destroy();
  return new NextResponse(JSON.stringify({ success: true }), {
    status: 200,
    headers: res.headers,
  });
}
Add Navigation Hook (Create hooks/useAuth.ts):

typescript
Copy
'use client';
import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { getSession } from '@/lib/session';

export function useAuth(redirectTo = '/login') {
  const router = useRouter();

  useEffect(() => {
    async function checkAuth() {
      const { session } = await getSession();
      if (!session?.user) {
        router.push(redirectTo);
      }
    }
    
    checkAuth();
  }, [router, redirectTo]);
}
Update Header Component (Example components/Header.tsx):

tsx
Copy
'use client';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

export function Header() {
  const router = useRouter();

  const handleLogout = async () => {
    await fetch('/api/logout', { method: 'POST' });
    router.push('/login');
  };

  return (
    <header className="bg-gray-800 text-white p-4">
      <div className="container mx-auto flex justify-between items-center">
        <Link href="/" className="text-xl font-bold">Your App</Link>
        <button
          onClick={handleLogout}
          className="bg-red-500 hover:bg-red-600 px-4 py-2 rounded"
        >
          Logout
        </button>
      </div>
    </header>
  );
}
Key Features:

Full-stack login flow with error handling

Protected routes via middleware

Session-based authentication

Automatic redirect to login for unauthenticated users

Logout functionality

Reusable auth hook for client-side protection

Responsive login page design

To use in protected pages:

tsx
Copy
// Example protected page
'use client';
import { useAuth } from '@/hooks/useAuth';

export default function ProtectedPage() {
  useAuth(); // Redirects to login if not authenticated
  
  return (
    <div>
      <Header />
      {/* Protected content */}
    </div>
  );
}
