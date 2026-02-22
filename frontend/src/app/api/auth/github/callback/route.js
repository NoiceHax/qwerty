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
                client_id: "Ov23lik7WUwQYjJsz774",
                client_secret: "9fca7fb72d2a7dd9679f59274b6629c36623463e",
                code,
            }),
        });

        const tokenData = await tokenRes.json();

        if (tokenData.error) {
            console.error("GitHub OAuth error:", tokenData);
            const errMsg = tokenData.error_description || tokenData.error;
            return NextResponse.redirect(
                new URL(`/login?error=${encodeURIComponent(errMsg)}`, request.url)
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
        const response = NextResponse.redirect("https://qwerty-iota-three.vercel.app/dashboard");

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
