import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import prisma from "../lib/prisma.js";

export const register = async (request, response) => {
  const { username, email, password } = request.body;

  try {
    //   Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    console.log(hashedPassword);

    // Create new user in db
    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
      },
    });

    console.log(newUser);

    response.status(201).json({ message: "User Created Successfully" });
  } catch (error) {
    console.log(error);
    response.status(500).json({ message: "Failed to create new user" });
  }
};

export const login = async (request, response) => {
  const { username, password } = request.body;

  try {
    // Check if user exist
    const user = await prisma.user.findUnique({
      where: { username },
    });

    if (!user) {
      return response.status(401).json({ message: "Invalid Credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return response.status(401).json({ message: "Invalid Credentials" });
    }

    // Generate cookie
    const age = 1000 * 60 * 60 * 24 * 7;
    const token = jwt.sign(
      {
        id: user.id,
      },
      process.env.JWT_SECRET_KEY,
      { expiresIn: age }
    );

    const { password: userPassword, ...userInfo } = user;

    response
      .cookie("token", token, {
        httpOnly: true,
        // secure: true
        maxAge: age,
      })
      .status(200)
      .json(userInfo);
  } catch (error) {
    console.log(error);
  }
};

export const logout = (request, response) => {
  response
    .clearCookie("token")
    .status(200)
    .json({ message: "Logout Successful" });
};
