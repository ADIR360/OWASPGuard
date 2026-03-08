import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './login.css';
import 'boxicons';
import googleIcon from '../img/google-icon.svg';
import { Link } from 'react-router-dom';

const Login = () => {
  const [isSignup, setIsSignup] = useState(false);
  const [signupData, setSignupData] = useState({ name: '', email: '', password: '' });
  const [loginData, setLoginData] = useState({ email: '', password: '' });
  const [message, setMessage] = useState('');
  const navigate = useNavigate();

  const toggleForm = () => {
    setIsSignup(!isSignup);
    setMessage('');
  };

  const handleSignupChange = (e) => {
    const { name, value } = e.target;
    setSignupData((prevData) => ({ ...prevData, [name]: value }));
  };

  const handleLoginChange = (e) => {
    const { name, value } = e.target;
    setLoginData((prevData) => ({ ...prevData, [name]: value }));
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:5000/api/users/signup', signupData);
      setMessage('Signup successful! Please log in.');
      toggleForm();
    } catch (error) {
      setMessage(error.response?.data?.message || 'Signup failed. Please try again.');
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:5000/api/users/login', loginData);
      setMessage('Login successful!');
      navigate('/vulnerabilities');
    } catch (error) {
      setMessage(error.response?.data?.message || 'Login failed. Please try again.');
    }
  };

  return (
    <div className='login-page'>
      <div className={`container ${isSignup ? 'right-panel-active' : ''}`} id="container">
        <div className="form-containerr sign-up-container">
          <form onSubmit={handleSignup}>
            <div className="xxxup">
              <h1>Create Account</h1>
              <div className="signup-buttons">
                <button type="button" className="google-signup">
                  <img src={googleIcon} alt="Google icon" style={{ width: '20px', marginRight: '5px' }} />Sign Up with Google
                </button>
                <button type="button" className="github-signup">
                  <box-icon type='logo' name='github' size='sm'></box-icon>Sign Up with GitHub
                </button>
              </div>
              <span>Or use your email for registration</span>
              <input type="text" placeholder="Name" name="name" value={signupData.name} onChange={handleSignupChange} required />
              <input type="email" placeholder="Email" name="email" value={signupData.email} onChange={handleSignupChange} required />
              <input type="password" placeholder="Password" name="password" value={signupData.password} onChange={handleSignupChange} required />
              <button id='click'>Sign Up</button>
            </div>
          </form>
        </div>
        <div className="form-containerr sign-in-container">
          <form onSubmit={handleLogin}>
            <div className="xxxin">
              <h1>Welcome Back!</h1>
              <div className="signup-buttons">
                <button type="button" className="google-signup">
                  <img src={googleIcon} alt="Google icon" style={{ width: '20px', marginRight: '5px' }} />Sign In with Google
                </button>
                <button type="button" className="github-signup">
                  <box-icon type='logo' name='github' size='sm'></box-icon>Sign In with GitHub
                </button>
              </div>
              <h3>Enter the Credentials to Login In.</h3>
              <input type="email" placeholder="Email ID" name="email" value={loginData.email} onChange={handleLoginChange} required />
              <input type="password" placeholder="Password" name="password" value={loginData.password} onChange={handleLoginChange} required />
              <Link id="forgot" to="#">Forgot your password?  </Link>
              <button>Sign In</button>
            </div>
          </form>
        </div>
        <div className="overlay-container">
          <div className="overlay">
            <div className="overlay-panel overlay-left">
              <h1>
                <span className="bounce welcome">Welcome</span> <span className="bounce back">Back!</span>
              </h1>
              <p>To keep connected with us please login with your personal info</p>
              <button className="ghost" id="signIn" onClick={toggleForm}>Sign In</button>
            </div>
            <div className="overlay-panel overlay-right">
              <h1>
                <span className="bounce hello">Hello,</span><span className="bounce friend">Friend!</span>
              </h1>
              <p>Enter your personal details and complete the form to start journey with us</p>
              <button className="ghost" id="signUp" onClick={toggleForm}>Sign Up</button>
            </div>
          </div>
        </div>
      </div>
      {message && <div className="message">{message}</div>}
    </div>
  );
};

export default Login;
