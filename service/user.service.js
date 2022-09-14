const UserModel = require("../models/user.model");
const bcrypt = require("bcrypt");
const uuid = require("uuid");
const mailService = require("./mail.service.js");
const tokenService = require("./token.service");
const UserDto = require("../dtos/user.dto");
const ApiErrors = require("../exceptions/api-errors");
const userModel = require("../models/user.model");

class UserService {
    async registration(email, password) {
        const candidate = await UserModel.findOne({ email });
        if (candidate) {
            throw ApiErrors.BadRequest(
                "Пользователь с таким имеилом уже существует"
            );
        }
        const hashPassword = await bcrypt.hash(password, 5);
        const activationLink = uuid.v4();
        const user = await UserModel.create({
            email,
            password: hashPassword,
            activationLink,
        });

        await mailService.sendActivationMail(
            email,
            `${process.env.API_URL}/api/active/${activationLink}`
        );

        const userDto = new UserDto(user);
        const tokens = await tokenService.generateToken({ ...userDto });
        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return { ...tokens, userDto };
    }

    async login(email, password) {
        const user = await UserModel.findOne({ email });
        if (!user) {
            throw ApiErrors.BadRequest("Пользователь не найден");
        }

        const isPassEquals = await bcrypt.compare(password, user.password);
        if (!isPassEquals) {
            throw ApiErrors.BadRequest("Неверный логин или пароль");
        }

        const userDto = new UserDto(user);
        const tokens = await tokenService.generateToken({ ...userDto });
        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return { ...tokens, userDto };
    }

    async logout(refreshToken) {
        const token = await tokenService.removeToken(refreshToken);
        return token;
    }

    async activate(activationLink) {
        const user = await UserModel.findOne({ activationLink });
        if (!user) {
            throw ApiErrors.BadRequest("Некорректная ссылка активации");
        }

        user.isActivated = true;
        await user.save();
    }

    async refresh(refreshToken) {
        if (!refreshToken) {
            throw ApiErrors.UnauthorizedError();
        }

        const userData = await tokenService.validateRefreshToken(refreshToken);
        const token = await tokenService.findToken(refreshToken);
        if (!token || !userData) {
            throw ApiErrors.UnauthorizedError();
        }

        const user = await UserModel.findById(userData.id);
        const userDto = new UserDto(user);
        const tokens = await tokenService.generateToken({ ...userDto });
        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return { ...tokens, userDto };
    }

    async getAllUsers() {
        const users = await userModel.find();
        return users;
    }
}

module.exports = new UserService();
