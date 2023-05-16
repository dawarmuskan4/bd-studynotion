const User = require("../models/User")
const OTP = require("../models/OTP") 
const otpGenerator = require("otp-generator")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
require("dotenv").config()
const mailSender = require("../utils/mailSender")

//send OTP
exports.sendOTP = async (req, res) => {
  try{
    //fetch email from request body
    const {email} = req.body

    //check if user already present
    const checkUserPresent = await User.findOne({email})

    //if user already present, then return a response
    if(checkUserPresent){ 
      return res.status(401).json({
        success: false,
        message: "User already present"
      })
    }

    //generate OTP
    var otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false
    })
    console.log("OTP Generated is ", otp)

    //check for unique otp
    let result = await OTP.findOne({otp: otp})
    while(result){
      otp = otpGenerator(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false
      })
      result = await OTP.findOne({otp: otp})
    }

    //create entry for the otp in database
    const otpPayload = {email, otp}

    const otpBody = await OTP.create(otpPayload)
    console.log("Otp entry created in db ", otpBody)

    //return response
    res.status(200).json({
      success: true,
      message: "OTP sent successfully"
    })

  } catch(error){
      console.log("Error generated while creating otp, ", error )
      return res.status(500).json({
        success: false,
        message: error.message
      })
  }
   
}


//signup
exports.signup = async (req, res) => {

  try{
    //fetch data from request body
    const {firstName, lastName, email, password, confirmPassword, accountType , contactNumber, otp} = req.body

    //validate data
    if(!firstName || !lastName || !email || !password || !confirmPassword || !otp){
      return res.status(403).json({
        success: false,
        message: "All fields are required "
      })
    }

    //match both the passwords
    if(password !== confirmPassword){
      return res.status(400).json({
        success: false,
        message: "Passwords do not match, try again"
      })
    }

    //check if user already exists
    const existingUser = await User.findOne({email})
    if(existingUser){
      return res.status(401).json({
        success: false,
        message: "User already registered"
      })
    }

    //find most recent OTP stored for the user
    const recentOtp = await OTP.find({email}).sort({createdAt: -1}).limit(1)
    console.log("Recent OTP ", recentOtp )

    //validate OTP
    if(recentOtp.length == 0){
      //otp not found
      return res.status(400).json({
        success: false,
        message: "OTP not found"
      })
    } else if (otp !== recentOtp){
      //invalid otp
      return res.status(400).json({
        success: false,
        message: "Invalid OTP"
      })
    }

    //hash password
    const hashedPassword = await bcrypt.hash(password, 10)

    //create entry in the db
    const profileDetails = await Profile.create({
      gender: null,
      dateOfBirth: null,
      about: null,
      contactNumber: null
    })

    const user = await User.create({
      firstName,
      lastName,
      email,
      contactNumber,
      password: hashedPassword,
      accountType,
      additionalDetails: profileDetails._id,
      image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`
    })

    //return response
    return res.status(200).json({
      success: true,
      message: "User registered successfully",
      user
    })

  } 
  catch(error){
    console.log("Error occurred while registering user ", error)
    return res.status(500).json({
      success: false,
      message: "User cannot be registered. Please try again"
    })
  }
  
}


//login
exports.login = async(req, res) => {
  try{
    //fetch data from request body
    const {email , password}  = req.body

    //validate data
    if(!email || !password){
      return res.status(403).json({
        success: false,
        message: "All fields are required, please try again"
      })
    }

    //check if user exists or not
    const user = await User.findOne({email}).populate("additionalDetails")
    if(!user){
      return res.status(401).json({
        success: false,
        message: "User is not registered, please signup first"
      })
    }

    //generate jwt, after matching password
    if(await bcrypt.compare(password, user.password)){
      const payload = {
        email : user.email,
        id: user._id,
        role: user.accountType
      }
      const token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "2h "
      })
      user.token = token
      user.password = undefined;

      //create cookie and send response
      const options = {
        expires: new Date(Date.now() + 3*24*60*60*1000),
        httpOnly: true
      }
      res.cookie("token", token, options).status(200).json({
        success: true,
        token,
        user,
        message: "Logged In Successfully"
      })
    }else{
      return res.status(401).json({
        success: false,
        message: "Password is incorrect"
      })
    }

    
  }
  catch(error){
    console.log("Error while logging in ", error)
    return res.status(500).json({
      success : false,
      message: "User couldn't be logged in , Please try again"
    })
  } 
}

// create Password
exports.changePassword = async (req, res) => {
  try{
    //get data from req.body
    const {email, password} = req.body
  
    //get oldPassword, newPassword, confirmNewPassword
    const { newPassword, confirmNewPassword} = req.body

    // validation
    if(newPassword !== confirmNewPassword){
      return res.status(401).json({
        success: true,
        message: "Password don't match, please try again"
      })
    } 

    //update password in database
    const updatedPassword = User.findByIdAndUpdate({password, newPassword})
    console.log("Password updated ", updatedPassword)

    //send mail - password updated
    mailSender(email, "Password Updated" , `<h2>Password has been changed for your account with email ${email}</h2>`)

    //return response
    return res.status(200).json({
      success: true,
      message : "Password Updated Successfully"
    })
  }
  catch(error){
    return res.status(500).json({
      success: false,
      message: "Error occurred while updating password"
    })
  }
}