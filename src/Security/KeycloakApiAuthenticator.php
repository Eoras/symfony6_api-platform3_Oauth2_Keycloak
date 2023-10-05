<?php

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use stdClass;
use Symfony\Component\DependencyInjection\ParameterBag\ContainerBagInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\Cache\TagAwareCacheInterface;

class KeycloakApiAuthenticator extends OAuth2Authenticator implements AuthenticationEntryPointInterface
{
    public function __construct(
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly TagAwareCacheInterface $cacheApp,
        private readonly ContainerBagInterface $containerBag,
        private readonly UserRepository $userRepository,

    )
    {
    }

    public function supports(Request $request): ?bool
    {
        return true;
    }

    public function authenticate(Request $request): Passport
    {
        // Get token from header
        $jwtToken = $request->headers->get('Authorization');
        if (false === str_starts_with($jwtToken, 'Bearer ')) {
            throw new AuthenticationException('Invalid token');
        }

        $jwtToken = str_replace('Bearer ', '', $jwtToken);

        // Decode the token
        $parts = explode('.', $jwtToken);
        if (count($parts) !== 3) {
            throw new AuthenticationException('Invalid token');
        }

        $headers = new stdClass();

        try {
            $decodedToken = JWT::decode($jwtToken, $this->getJwks(), $headers);
        } catch (Exception $e) {
            throw new AuthenticationException($e->getMessage());
        }

        return new SelfValidatingPassport(
            new UserBadge($decodedToken->sub, function (string $keycloakId) use ($decodedToken) {

                $existingUser = $this->userRepository->findOneBy(['keycloakId' => $keycloakId]);
                if ($existingUser) {
                    return $existingUser;
                }

                // 2) do we have a matching user by email?
                $user = $this->userRepository->findOneBy(['email' => $decodedToken->email]);

                if(!$user) {
                    $user = new User;
                    $user->setEmail($decodedToken->email);
                    $user->setPassword($this->passwordHasher->hashPassword(
                        $user,
                        random_bytes(15)
                    ));
                    $this->userRepository->add($user);
                }

                // 3) Maybe you just want to "register" them by creating a User object
                $user->setKeycloakId($keycloakId);
                $this->userRepository->flush();

                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?JsonResponse
    {
        $data = [
            'error' => strtr($exception->getMessageKey(), $exception->getMessageData())
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function start(Request $request, AuthenticationException $authException = null): RedirectResponse
    {
        return new RedirectResponse(
            '/connect/keycloak',
            Response::HTTP_TEMPORARY_REDIRECT
        );
    }
    private function getJwks(): array
    {
        $jwkData = $this->cacheApp->get('jwk_keys', function (ItemInterface $item) {
            $jwkData = json_decode(
                file_get_contents(
                    $this->containerBag->get('OAUTH_KEYCLOAK_APP_CERTS')
                ),
                true
            );

            $item->expiresAfter(3600);
            $item->tag(['authentication']);

            return $jwkData;
        });

        return JWK::parseKeySet($jwkData);
    }
}
