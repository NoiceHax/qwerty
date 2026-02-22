import { NextResponse } from "next/server";

export async function GET(request) {
    const { searchParams } = new URL(request.url);
    const code = searchParams.get("code");

    if (!code) {
        return NextResponse.redirect(new URL("/login?error=no_code", request.url));
    }

    try {
        // Exchange code for access token
        const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
            },
            body: JSON.stringify({
                client_id: process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID,
                client_secret: process.env.GITHUB_CLIENT_SECRET,
                code,
            }),
        });

        const tokenData = await tokenRes.json();

        if (tokenData.error) {
            console.error("GitHub OAuth error:", tokenData);
            return NextResponse.redirect(
                new URL(`/login?error=${tokenData.error}`, request.url)
            );
        }

        const accessToken = tokenData.access_token;

        // Verify the token works by fetching user info
        const userRes = await fetch("https://api.github.com/user", {
            headers: { Authorization: `Bearer ${accessToken}` },
        });

        if (!userRes.ok) {
            return NextResponse.redirect(
                new URL("/login?error=invalid_token", request.url)
            );
        }

        // Set cookie and redirect to dashboard
        const response = NextResponse.redirect(new URL("/dashboard", request.url));

        response.cookies.set("github_token", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            path: "/",
            maxAge: 60 * 60 * 24 * 7, // 7 days
        });

        return response;
    } catch (err) {
        console.error("OAuth callback error:", err);
        return NextResponse.redirect(
            new URL("/login?error=server_error", request.url)
        );
    }
}
