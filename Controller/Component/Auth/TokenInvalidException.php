<?php
class TokenInvalidException extends CakeException
{
    const ERROR_CODE = 403;

    private $refreshToken = null;

    public function __construct($refreshToken)
    {
        $this->refreshToken = $refreshToken;
        parent::__construct('Token invalid', self::ERROR_CODE);
    }
}
