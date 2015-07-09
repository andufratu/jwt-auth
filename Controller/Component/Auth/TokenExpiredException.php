<?php
class TokenExpiredException extends CakeException
{
    const ERROR_CODE = 401;

    private $refreshToken = null;

    public function __construct($refreshToken)
    {
        $this->refreshToken = $refreshToken;
        parent::__construct('Token expired', self::ERROR_CODE);
    }

    public function getRefreshToken()
    {
        return $this->refreshToken;
    }
}
