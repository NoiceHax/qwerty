import { NextResponse } from "next/server";
import { cookies } from "next/headers";

export async function GET() {
    const cookieStore = await cookies();
    const token = cookieStore.get("github_token")?.value;

    if (!token) {
        return NextResponse.json({ authenticated: false }, { status: 401 });
    }

    try {
        const userRes = await fetch("https://api.github.com/user", {
            headers: { Authorization: `Bearer ${token}` },
            cache: "no-store",
        });

        if (!userRes.ok) {
            return NextResponse.json({ authenticated: false }, { status: 401 });
        }

        const user = await userRes.json();

        return NextResponse.json({
            authenticated: true,
            user: {
                login: user.login,
                name: user.name,
                avatar_url: user.avatar_url,
                html_url: user.html_url,
                public_repos: user.public_repos,
                bio: user.bio,
            },
        });
    } catch {
        return NextResponse.json({ authenticated: false }, { status: 500 });
    }
}
