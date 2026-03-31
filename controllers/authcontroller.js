const User = require('../../backend/models/User');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

// ----------------------------------------------------
// BREVO (SMTP) NODEMAILER SETUP
// ----------------------------------------------------
const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.BREVO_SMTP_LOGIN, // Ye aapki .env file se aayega (e.g., a228... wala id)
    pass: process.env.BREVO_SMTP_KEY,   // Ye aapki .env file se aayega (lamba sa password)
  },
});

// 1. FORGOT PASSWORD (Email bhejna)
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    // Agar user nahi mila
    if (!user) {
      return res.status(404).json({ message: 'This email is not registered with us.' });
    }

    // Ek random token generate karein
    const resetToken = crypto.randomBytes(20).toString('hex');

    // Token ko hash karke database mein save karein
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpire = Date.now() + 15 * 60 * 1000; // 15 minute ke liye valid

    await user.save();

    // Frontend URL jahan user redirect hoga
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

    // Email ka format aur details
    const mailOptions = {
      // 👇 DHYAN DEIN: Yahan 'aapki.asli.email@gmail.com' ko hata kar apni wahi email daalein jisse Brevo account banaya hai 👇
      from: '"AuthApp Support" <anujsingh20078@gmail.com>', 
      to: user.email,
      subject: 'Password Reset Request',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>Hi ${user.name},</p>
          <p>You requested a password reset. Please click the button below to set a new password:</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetUrl}" style="background-color: #6366f1; color: white; padding: 12px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">
              Reset My Password
            </a>
          </div>
          <p style="color: #777; font-size: 14px;">This link is valid for 15 minutes. If you didn't request this, please ignore this email.</p>
        </div>
      `,
    };

    // Brevo ke zariye Email Bhejein
    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent via Brevo: %s", info.messageId);

    res.status(200).json({ message: 'Reset link sent to email successfully.' });

  } catch (error) {
    console.error("Error sending email:", error);
    
    // Agar email bhejne mein fail ho jaye, toh DB se token hata dein (Cleanup)
    if (req.body.email) {
      const user = await User.findOne({ email: req.body.email });
      if (user) {
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save();
      }
    }

    res.status(500).json({ message: 'Error sending email. Please try again later.' });
  }
};


// 2. RESET PASSWORD (Naya password save karna)
exports.resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token.' });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.status(200).json({ message: 'Password has been reset successfully.' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error. Please try again.' });
  }
};