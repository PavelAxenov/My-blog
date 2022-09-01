import jwt from 'jsonwebtoken';
import bcrypt, { compareSync } from 'bcrypt';
import UserModel from '../models/user.js';



export const register = async (req, res) => {
    try {

    //Шифруем пароль
    const password = req.body.password;
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);


    // Создаем документ
    const doc = new UserModel({
        email: req.body.email,
        fullName: req.body.fullName,
        avatarUrl: req.body.avatarUrl,
        passwordHash: hash,
    })

    // Создаем пользователя
    const user = await doc.save();

    const token = jwt.sign({
            _id: user._id
        },
        'secret123',
        {
            expiresIn: '300d'
        }
    );

    const {passwordHash, ...userData} = user._doc;

    res.json({
        ...userData,
        token
    }); // возврат информации о пользователе

    } catch (error) {
        // Обработка ошибки регистрации
        console.log(error);        
        res.status(500).json({
            message: 'Не удалось зарегестрироваться',
        })
    }
};

export const login = async (req, res) => {
    try {
        const user = await UserModel.findOne({email: req.body.email});

        if (!user) {
            return req.status(404).json({
                message: 'Пользователь не найден'
            })
        }

        const isValidPass = await bcrypt.compare(req.body.password, user._doc.passwordHash);
        if (!isValidPass) {
            return res.status(400).json({
                message: 'Неверный логин или пароль'
            })
        }

        const token = jwt.sign({
            _id: user._id
        },
        'secret123',
        {
            expiresIn: '300d'
        }
    );

    const {passwordHash, ...userData} = user._doc;

    res.json({
        ...userData,
        token
    }); // возврат информации о пользователе

    } catch (err) {
        // Обработка ошибки регистрации
        console.log(err);        
        res.status(500).json({
            message: 'Не удалось авторизоваться',
        })
    }
};

export const getMe = async (req, res) => {
    try {
        const user = await UserModel.findById(req.userId)

        if (!user) {
            return res.status(404).json({
                message: "Пользователь не найден"
            });
        }

        const {passwordHash, ...userData} = user._doc;

        res.json(userData); // возврат информации о пользователе
    } catch (err) {
        // Обработка ошибки регистрации
        console.log(err);        
        res.status(500).json({
            message: 'Не удалось зарегестрироваться',
        })
    }
}