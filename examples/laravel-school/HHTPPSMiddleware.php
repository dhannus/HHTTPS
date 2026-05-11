<?php
/**
 * Example: Laravel middleware + controller for a school messaging system
 * where ONLY verified teachers can post announcements to parent groups.
 *
 * Demonstrates:
 *   - HHTTPS token verification in PHP via Firebase\JWT\JWT
 *   - JWKS caching with file-based fallback
 *   - Trust-score thresholds for teachers (≥ 86)
 *   - Per-class role check
 *
 * Install:
 *   composer require firebase/php-jwt
 *
 * Wire up:
 *   // app/Http/Kernel.php
 *   protected $routeMiddleware = [
 *       'hhttps' => \App\Http\Middleware\HHTPPSMiddleware::class,
 *   ];
 *
 *   // routes/web.php
 *   Route::post('/announcement', [AnnouncementController::class, 'store'])
 *        ->middleware('hhttps:teacher,86');
 */

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

class HHTPPSMiddleware
{
    private const ISSUER_BASE  = 'https://hhttps.org';
    private const JWKS_CACHE   = '/tmp/hhttps_jwks_cache.json';
    private const JWKS_TTL_SEC = 3600;

    /**
     * @param Request $request
     * @param Closure $next
     * @param string  $requiredRole  e.g. 'teacher' or '*'
     * @param int     $minTrust      minimum trust score
     */
    public function handle(Request $request, Closure $next, string $requiredRole = '*', int $minTrust = 60)
    {
        $token = $request->header('HHTTPS-Token');
        if (! $token) {
            $auth = $request->header('Authorization', '');
            if (str_starts_with($auth, 'Bearer ')) {
                $token = substr($auth, 7);
            }
        }

        if (! $token) {
            return response()->json(['error' => 'HHTTPS token required'], 401);
        }

        try {
            $jwks    = $this->getJwks();
            $keys    = JWK::parseKeySet($jwks);
            $decoded = (array) JWT::decode($token, $keys);
        } catch (\Throwable $e) {
            return response()->json(['error' => 'Invalid token: ' . $e->getMessage()], 401);
        }

        $trust = $decoded['trustScore'] ?? 0;
        if ($trust < $minTrust) {
            return response()->json([
                'error'    => "Trust score too low (need ≥ $minTrust, got $trust)",
            ], 403);
        }

        if ($requiredRole !== '*' && ($decoded['role'] ?? null) !== $requiredRole) {
            return response()->json([
                'error'    => "Role '" . ($decoded['role'] ?? '?') . "' not allowed; required: $requiredRole",
            ], 403);
        }

        // Attach decoded HHTTPS claims to the request for downstream use
        $request->attributes->set('hhttps', $decoded);

        return $next($request);
    }

    /**
     * Get JWKS, cached on disk for 1 hour.
     */
    private function getJwks(): array
    {
        if (file_exists(self::JWKS_CACHE)
            && (time() - filemtime(self::JWKS_CACHE)) < self::JWKS_TTL_SEC) {
            return json_decode(file_get_contents(self::JWKS_CACHE), true);
        }

        $body = file_get_contents(self::ISSUER_BASE . '/.well-known/jwks.json');
        if ($body === false) {
            throw new \RuntimeException('Could not fetch JWKS from ' . self::ISSUER_BASE);
        }
        @file_put_contents(self::JWKS_CACHE, $body);
        return json_decode($body, true);
    }
}


// ─── Example controller ─────────────────────────────────────────────────────
namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AnnouncementController extends Controller
{
    /**
     * POST /announcement
     * Middleware: 'hhttps:teacher,86'
     *
     * Only verified teachers (role=teacher, trust ≥ 86) can post.
     * Parents see a verified badge on the announcement.
     */
    public function store(Request $request)
    {
        $request->validate([
            'classId' => 'required|string|max:50',
            'title'   => 'required|string|max:200',
            'message' => 'required|string|max:5000',
        ]);

        $hhttps = $request->attributes->get('hhttps');

        // No personal data is stored. Only:
        //  - The teacher's HHTTPS role + verification level
        //  - A partial JTI for later revocation matching
        //  - The trust score, so parents see "verified by Lehrer-ID + Schul-E-Mail"
        $announcement = [
            'classId'      => $request->input('classId'),
            'title'        => $request->input('title'),
            'message'      => $request->input('message'),
            'createdAt'    => now()->toIso8601String(),
            'verifiedBy'   => [
                'role'         => $hhttps['role'],
                'roleLevel'    => $hhttps['roleLevel'],   // e.g. "teacher-id" or "school-email"
                'trustScore'   => $hhttps['trustScore'],  // e.g. 86
                'issuer'       => $hhttps['iss'],
                'jtiPartial'   => substr($hhttps['jti'], 0, 16),
            ],
        ];

        // In real app: save to DB. Here we echo it back.
        return response()->json([
            'ok'           => true,
            'announcement' => $announcement,
        ], 201);
    }

    /**
     * GET /announcement/{id}
     * Public — anyone can read; verification info is shown alongside.
     */
    public function show(Request $request, string $id)
    {
        // ... fetch from DB ...
        return response()->json([
            'id'         => $id,
            'title'      => 'Sample announcement',
            'message'    => 'This is a sample announcement from a verified teacher.',
            'verifiedBy' => [
                'role'        => 'teacher',
                'trustScore'  => 86,
                'roleLevel'   => 'teacher-id',
                'displayHint' => '👨‍🏫 Verifizierter Lehrer · Trust 86',
            ],
        ]);
    }
}
