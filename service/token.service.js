const jwt = require("jsonwebtoken");
const TokenModel = require("../models/token.model");

class TokenService {
    async generateToken(payload) {
        const accessToken = await jwt.sign(
            payload,
            process.env.JWT_ACCESS_TOKEN,
            { expiresIn: "15m" }
        );
        const refreshToken = await jwt.sign(
            payload,
            process.env.JWT_REFRESH_TOKEN,
            { expiresIn: "30d" }
        );

        return {
            accessToken,
            refreshToken,
        };
    }

    async validateAccessToken(token) {
        try {
            const userData = await jwt.verify(
                token,
                process.env.JWT_ACCESS_TOKEN
            );
            return userData;
        } catch (e) {
            return null;
        }
    }

    async validateRefreshToken(token) {
        try {
            const userData = await jwt.verify(
                token,
                process.env.JWT_REFRESH_TOKEN
            );
            return userData;
        } catch (e) {
            return null;
        }
    }

    async saveToken(userId, refreshToken) {
        const tokenData = await TokenModel.findOne({ user: userId });
        if (tokenData) {
            tokenData.refreshToken = refreshToken;
            return tokenData.save();
        }
        const token = await TokenModel.create({ user: userId, refreshToken });
        return token;
    }

    async removeToken(refreshToken) {
        const tokenData = await TokenModel.deleteOne({ refreshToken });
        return tokenData;
    }

    async findToken(refreshToken) {
        const tokenData = await TokenModel.findOne({ refreshToken });
        return tokenData;
    }
}

module.exports = new TokenService();
