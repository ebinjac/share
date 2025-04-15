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


Update session.ts (fix type declarations and parameters):

typescript
Copy
// lib/session.ts
import { getIronSession, IronSessionData } from 'iron-session';

declare module 'iron-session' {
  interface IronSessionData {
    user?: {
      username: string;
      groups: string[];
    };
  }
}

const sessionOptions = {
  password: process.env.SESSION_SECRET!,
  cookieName: 'ldap-auth',
  cookieOptions: {
    secure: process.env.NODE_ENV === 'production',
  },
};

export async function getSession(req: Request) {
  const res = new Response();
  const session = await getIronSession<IronSessionData>(req, res, sessionOptions);
  return { session, res };
}

export type Session = Awaited<ReturnType<typeof getSession>>['session'];
Fix login route implementation (app/api/login/route.ts):

typescript
Copy
import { NextResponse } from 'next/server';
import { authenticateUser } from '@/lib/ldap';
import { getSession } from '@/lib/session';

export async function POST(request: Request) {
  const { username, password } = await request.json();
  
  try {
    const user = await authenticateUser(username, password);
    const { session, res } = await getSession(request);
    
    session.user = {
      username: user.username,
      groups: user.groups
    };
    
    await session.save();
    
    return new NextResponse(
      JSON.stringify({ success: true }), 
      {
        status: 200,
        headers: res.headers
      }
    );
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid credentials' },
      { status: 401 }
    );
  }
}


Update the LDAP authentication utility (lib/ldap.ts):

typescript
Copy
export async function authenticateUser(username: string, password: string) {
  // ... existing code ...

  // Convert group CN values to strings explicitly
  const groups = searchEntries.map((group) => {
    if (Array.isArray(group.cn)) {
      return group.cn.map(cn => cn.toString()).filter(Boolean);
    }
    return [group.cn?.toString() || ''].filter(Boolean);
  }).flat();

  return {
    username,
    groups: groups as string[], // Explicit type assertion
  };
}
Update the session type declaration (lib/session.ts):

typescript
Copy
declare module 'iron-session' {
  interface IronSessionData {
    user?: {
      username: string;
      groups: string[]; // Ensure type matches
    };
  }
}
Verify the login route (app/api/login/route.ts):

typescript
Copy
export async function POST(request: Request) {
  const { username, password } = await request.json();
  
  try {
    const user = await authenticateUser(username, password);
    const { session, res } = await getSession(request);
    
    // Explicit type check
    if (Array.isArray(user.groups) && user.groups.every(g => typeof g === 'string')) {
      session.user = {
        username: user.username,
        groups: user.groups
      };
    } else {
      throw new Error('Invalid group format from LDAP');
    }
    
    await session.save();
    
    return new NextResponse(
      JSON.stringify({ success: true }), 
      {
        status: 200,
        headers: res.headers
      }
    );
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { error: 'Invalid credentials' },
      { status: 401 }
    );
  }
}
Install Required Dependencies

bash
Copy
npm install ldapts iron-session drizzle-orm @types/cookie
Configure LDAP Utility (lib/ldap.ts)

typescript
Copy
import { Client } from 'ldapts';

const LDAP_CONFIG = {
  URL: process.env.LDAP_SERVER_URL || 'ldaps://localhost:636',
  BIND_DN: process.env.LDAP_BIND_DN || 'CN=svc.admin,OU=ServiceAccounts,OU=Process,DC=ads,DC=aexp,DC=com',
  BIND_CREDENTIALS: process.env.LDAP_BIND_CREDENTIALS || 'password',
  BASE_DN: process.env.LDAP_BASE_DN || 'dc=ads,dc=aexp,dc=com',
};

export async function authenticateUser(username: string, password: string) {
  const client = new Client({
    url: LDAP_CONFIG.URL,
    tlsOptions: { rejectUnauthorized: false },
  });

  try {
    // Bind with service account
    await client.bind(LDAP_CONFIG.BIND_DN, LDAP_CONFIG.BIND_CREDENTIALS);

    // Search for user
    const { searchEntries } = await client.search(LDAP_CONFIG.BASE_DN, {
      scope: 'sub',
      filter: `(uid=${username})`,
    });

    if (!searchEntries.length) throw new Error('User not found');
    const userDN = searchEntries[0].dn;

    // Verify user credentials
    await client.bind(userDN, password);

    // Get user groups
    const { searchEntries: groups } = await client.search('ou=Groups,dc=ads,dc=aexp,dc=com', {
      scope: 'sub',
      filter: `(member=${userDN})`,
      attributes: ['cn'],
    });

    return {
      username,
      groups: groups.map((g) => g.cn),
    };
  } finally {
    await client.unbind();
  }
}
Configure Session Management (lib/session.ts)

typescript
Copy
import { getIronSession, createResponse } from 'iron-session';

declare module 'iron-session' {
  interface IronSessionData {
    user?: {
      username: string;
      groups: string[];
    };
  }
}

const sessionOptions = {
  password: process.env.SESSION_SECRET!,
  cookieName: 'ldap-auth',
  cookieOptions: {
    secure: process.env.NODE_ENV === 'production',
  },
};

export async function getSession(req: Request, res: Response) {
  return getIronSession(req, res, sessionOptions);
}
Create Login API Route (app/api/login/route.ts)

typescript
Copy
import { NextResponse } from 'next/server';
import { authenticateUser } from '@/lib/ldap';
import { getSession } from '@/lib/session';

export async function POST(request: Request) {
  const { username, password } = await request.json();
  
  try {
    const user = await authenticateUser(username, password);
    const session = await getSession(request);
    
    session.user = user;
    await session.save();
    
    return NextResponse.json({ success: true });
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid credentials' },
      { status: 401 }
    );
  }
}
Create Authorization Middleware (middleware.ts)

typescript
Copy
import { NextResponse } from 'next/server';
import { getSession } from './lib/session';
import { eq } from 'drizzle-orm';
import { db } from './db';
import { teamsTable } from './db/schema';

export async function middleware(request: NextRequest) {
  const session = await getSession(request);
  const path = request.nextUrl.pathname;

  // Protect team routes
  if (path.startsWith('/teams/')) {
    if (!session.user) {
      return NextResponse.redirect(new URL('/login', request.url));
    }

    const teamId = path.split('/')[2];
    const team = await db.select()
      .from(teamsTable)
      .where(eq(teamsTable.id, teamId))
      .get();

    if (!team) return NextResponse.next();

    if (!session.user.groups.includes(team.prcGroup)) {
      return NextResponse.redirect(new URL('/unauthorized', request.url));
    }
  }

  return NextResponse.next();
}
Create Team Page with Authorization (app/teams/[id]/page.tsx)

typescript
Copy
import { db } from '@/db';
import { eq } from 'drizzle-orm';
import { teamsTable } from '@/db/schema';
import { getSession } from '@/lib/session';

export default async function TeamPage({ params }: { params: { id: string } }) {
  const session = await getSession();
  const team = await db.select()
    .from(teamsTable)
    .where(eq(teamsTable.id, params.id))
    .get();

  if (!team) return <div>Team not found</div>;
  
  return (
    <div>
      <h1>{team.teamName}</h1>
      {/* Team details */}
    </div>
  );
}
Add Environment Variables (.env.local)

