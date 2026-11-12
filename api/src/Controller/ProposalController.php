<?php

declare(strict_types=1);

namespace RiskStudio\Controller;

use PDO;
use RiskStudio\Http\HttpException;
use RiskStudio\Http\Request;
use RiskStudio\Http\Response;
use RiskStudio\Repository\RiskInput;
use RiskStudio\Repository\ValidationException;
use RiskStudio\Security\RateLimiter;

/**
 * Public "Proposer un risque" endpoint. Runs as rs_read: the database only
 * lets it insert a proposal without choosing its status, so a proposal is
 * always pending, whatever the request contains.
 *
 * Anti-abuse: honeypot field, 5 proposals per hour per client, 100 per day in
 * total, 32 KB body limit. The client is identified by an HMAC of its IP
 * address: no IP is stored.
 */
final class ProposalController
{
    public const PER_CLIENT_HOUR = 5;
    public const PER_DAY = 100;

    public function __construct(
        private readonly PDO $pdo,
        private readonly RateLimiter $limiter,
    ) {
    }

    public function create(Request $request): Response
    {
        $body = $request->json();

        // Bots fill every field; people never see this one.
        if (($body['website'] ?? '') !== '') {
            return Response::json(['status' => 'received'], 202);
        }

        $kind = $body['kind'] ?? '';
        if (!in_array($kind, ['risk', 'correction'], true)) {
            throw HttpException::badRequest('kind must be risk or correction.');
        }

        $errors = [];
        $name = RiskInput::clean($body['submitter_name'] ?? '');
        if (mb_strlen($name) > 100) {
            $errors['submitter_name'] = '100 caractères au maximum.';
        }
        $email = trim(is_string($body['submitter_email'] ?? null) ? $body['submitter_email'] : '');
        if ($email !== '' && (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false)) {
            $errors['submitter_email'] = 'Adresse e-mail invalide.';
        }
        if ($email !== '' && ($body['consent'] ?? false) !== true) {
            $errors['consent'] = 'Votre accord est nécessaire pour conserver votre adresse e-mail.';
        }

        $payload = is_array($body['payload'] ?? null) ? $body['payload'] : [];
        try {
            $clean = $kind === 'risk' ? $this->risk($payload) : $this->correction($payload);
        } catch (ValidationException $e) {
            $errors += $e->fields;
        }
        if ($errors !== []) {
            throw new ValidationException($errors);
        }

        if (!$this->limiter->hit('proposal-client', $request->ip, self::PER_CLIENT_HOUR, 3600)
            || !$this->limiter->hit('proposal-all', 'global', self::PER_DAY, 86400)) {
            throw new HttpException(429, 'too_many_proposals', 'Trop de propositions récentes. Merci de réessayer plus tard.');
        }

        $this->pdo->prepare(
            'INSERT INTO proposals (kind, payload, submitter_name, submitter_email, client_fingerprint) VALUES (?, ?, ?, ?, ?)'
        )->execute([
            $kind,
            json_encode($clean, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR),
            $name === '' ? null : $name,
            $email === '' ? null : $email,
            $this->limiter->bucket('fingerprint', $request->ip),
        ]);

        return Response::json(['status' => 'received'], 202);
    }

    /** @param array<string, mixed> $p @return array<string, mixed> */
    private function risk(array $p): array
    {
        $data = RiskInput::validate($p, $this->pdo);
        $references = RiskInput::clean($p['references'] ?? '');
        if (mb_strlen($references) > 500) {
            throw new ValidationException(['references' => '500 caractères au maximum.']);
        }

        return [
            'title' => $data['title'],
            'category' => $data['category'],
            'threat' => $data['threat'],
            'scenario' => $data['scenario'],
            'measures' => $data['measures'],
            'impact' => $data['impact'],
            'cia' => ($data['cia']['C'] ? 'C' : '') . ($data['cia']['I'] ? 'I' : '') . ($data['cia']['A'] ? 'A' : ''),
            'environment' => $data['environment'],
            'sectors' => $data['sectors'],
            'references' => $references,
        ];
    }

    /** @param array<string, mixed> $p @return array<string, mixed> */
    private function correction(array $p): array
    {
        $code = is_string($p['risk_code'] ?? null) ? strtoupper($p['risk_code']) : '';
        $message = RiskInput::clean($p['message'] ?? '');
        $errors = [];
        $stmt = $this->pdo->prepare('SELECT COUNT(*) FROM v_public_risks WHERE code = ?');
        $stmt->execute([$code]);
        if ((int) $stmt->fetchColumn() !== 1) {
            $errors['risk_code'] = 'Risque inconnu.';
        }
        if (mb_strlen($message) < 10 || mb_strlen($message) > 2000) {
            $errors['message'] = 'Entre 10 et 2000 caractères.';
        }
        if ($errors !== []) {
            throw new ValidationException($errors);
        }

        return ['risk_code' => $code, 'message' => $message];
    }
}
