const ApiErrors = require("../exceptions/api-errors");
const tokenService = require("../service/token.service");

module.exports = async function (req, res, next) {
    try {
        const authorizationHeaders = req.headers.authorization;
        if (!authorizationHeaders) {
            return next(ApiErrors.UnauthorizedError());
        }

        const accessToken = authorizationHeaders.split(" ")[1];
        if (!accessToken) {
            return next(ApiErrors.UnauthorizedError());
        }

        const userData = await tokenService.validateAccessToken(accessToken);
        if (!userData) {
            return next(ApiErrors.UnauthorizedError());
        }

        req.user = userData;
        next();
    } catch (e) {
        return next(ApiErrors.UnauthorizedError());
    }
};
