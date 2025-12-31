const modelUser = require('../models/users.model');
const modelApiKey = require('../models/apiKey.model');

const bcrypt = require('bcrypt');

const { BadRequestError } = require('../core/error.response');
const { Created, OK } = require('../core/success.response');

const { createApiKey, createRefreshToken, createToken, verifyToken } = require('../services/tokenSevices');
const jwt = require('jsonwebtoken');
const otpGenerator = require('otp-generator');

require('dotenv').config();
class controllerUser {
    async register(req, res) {
        const { fullName, email, password, phone, address } = req.body;

        if (!fullName || !email || !password || !phone) {
            throw new BadRequestError('Vui lòng nhập đày đủ thông tin');
        }
        const user = await modelUser.findOne({ email });
        if (user) {
            throw new BadRequestError('Người dùng đã tồn tại');
        } else {
            const saltRounds = 10;
            const salt = bcrypt.genSaltSync(saltRounds);
            const passwordHash = bcrypt.hashSync(password, salt);
            const newUser = await modelUser.create({
                fullName,
                email,
                password: passwordHash,
                typeLogin: 'email',
                address,
                phone,
            });
            await newUser.save();
            await createApiKey(newUser._id);
            const token = await createToken({ id: newUser._id });
            const refreshToken = await createRefreshToken({ id: newUser._id });
            res.cookie('token', token, {
                httpOnly: true, // Chặn truy cập từ JavaScript (bảo mật hơn)
                secure: true, // Chỉ gửi trên HTTPS (để đảm bảo an toàn)
                sameSite: 'Strict', // Chống tấn công CSRF
                maxAge: 15 * 60 * 1000, // 15 phút
            });

            res.cookie('logged', 1, {
                httpOnly: false,
                secure: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
            });

            // Đặt cookie HTTP-Only cho refreshToken
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
            });
            new Created({ message: 'Đăng ký thành công', metadata: { token, refreshToken } }).send(res);
        }
    }

    async loginGoogle(req, res) {
        const { credential } = req.body;
        const dataToken = jwtDecode(credential);
        const user = await modelUser.findOne({ email: dataToken.email });
        if (user) {
            await createApiKey(user._id);
            const token = await createToken({ id: user._id });
            const refreshToken = await createRefreshToken({ id: user._id });
            res.cookie('token', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 15 * 60 * 1000, // 15 phút
            });
            res.cookie('logged', 1, {
                httpOnly: false,
                secure: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
            });
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
            });
            new OK({
                message: 'Đăng nhập thành công',
                metadata: {
                    token,
                    refreshToken,
                    isAdmin: findUser.isAdmin,
                },
            }).send(res);
        } else {
            const newUser = await modelUser.create({
                fullName: dataToken.name,
                email: dataToken.email,
                typeLogin: 'google',
            });
            await newUser.save();
            await createApiKey(newUser._id);
            const token = await createToken({ id: newUser._id });
            const refreshToken = await createRefreshToken({ id: newUser._id });
            res.cookie('token', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 15 * 60 * 1000, // 15 phút
            });
            res.cookie('logged', 1, {
                httpOnly: false,
                secure: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
            });
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
            });
            new OK({
                message: 'Đăng nhập thành công',
                metadata: {
                    token,
                    refreshToken,
                    isAdmin: findUser.isAdmin,
                },
            }).send(res);
        }
    }
    async login(req, res) {
        const { email, password } = req.body;
        const findUser = await modelUser.findOne({ email });
        if (!findUser) {
            throw new BadRequestError('Tài khoản hoặc mật khẩu không chính xác !!!');
        }

        if (findUser.typeLogin === 'google') {
            throw new BadRequestError('Vui lòng đăng nhập bằng Google');
        }

        const result = await bcrypt.compare(password, findUser.password);

        if (!result) {
            throw new BadRequestError('Tài khoản hoặc mật khẩu không chính xác !!!');
        }
        if (result) {
            await createApiKey(findUser._id);
            const token = await createToken({ id: findUser._id });
            const refreshToken = await createRefreshToken({ id: findUser._id });
            res.cookie('token', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 15 * 60 * 1000, // 15 phút
            });

            res.cookie('logged', 1, {
                httpOnly: false,
                secure: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
            });

            // Đặt cookie HTTP-Only cho refreshToken
            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: true,
                sameSite: 'Strict',
                maxAge: 7 * 24 * 60 * 60 * 1000, // 7 ngày
            });
            new OK({
                message: 'Đăng nhập thành công',
                metadata: {
                    token,
                    refreshToken,
                    isAdmin: findUser.isAdmin,
                },
            }).send(res);
        }
    }
}

module.exports = new controllerUser();
