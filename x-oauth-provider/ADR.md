# Decision

Implement X OAuth client-provider following the same architecture as the GitHub OAuth provider, with the following key differences:

1. **X API Specifics**: Use X's OAuth 2.0 endpoints and user info structure
2. **Scope Defaults**: Default to `"users.read tweet.read offline.access"` for X-specific permissions
3. **User Data Structure**: Adapt to X's user object format (username, profile_image_url, verified)
4. **Rate Limiting**: Consider X's stricter rate limits for API calls

# Context

X (formerly Twitter) uses OAuth 2.0 with PKCE, similar to GitHub but with different:

- API endpoints (`api.x.com` vs `api.github.com`)
- Authorization server (`x.com/i/oauth2/authorize`)
- Token endpoint (`api.x.com/2/oauth2/token`)
- User info endpoint (`api.x.com/2/users/me`)
- Scope format (space-separated vs comma-separated)

# Consequences

- Maintains the same domain-based client identification pattern
- Provides consistent developer experience across GitHub and X OAuth
- Supports both direct login and OAuth provider flows
- Rate limiting considerations for X API calls (especially /users/me)
