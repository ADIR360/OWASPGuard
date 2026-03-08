import React, { useState, useRef, useCallback, useEffect } from 'react';
import emailjs from '@emailjs/browser';
import LocomotiveScroll from 'locomotive-scroll';
import './ContactContent.css';
import { Helmet, HelmetProvider } from 'react-helmet-async';

const ContactContent = () => {
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    topic: '',
    message: ''
  });

  const [feedback, setFeedback] = useState('');
  const formRef = useRef(null);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
  };

  const handleSubmit = useCallback((e) => {
    e.preventDefault();

    emailjs.sendForm('service_7c9qd09', 'template_h6gq1m2', formRef.current, 'HnM8VT7Sq8Mc3wvpd')
      .then(
        () => {
          setFeedback('Look at the stars Look how they shine for you And everything you do Yeah, they were all yellow');
          setFormData({
            firstName: '',
            lastName: '',
            email: '',
            topic: '',
            message: ''
          });
        },
        (error) => {
          setFeedback(`FAILED... ${error.text}`);
        },
      );

  }, []);

  useEffect(() => {
    const locomotiveScroll = new LocomotiveScroll({
      el: document.querySelector('#scroll-container'),
      smooth: true,
    });
    return () => locomotiveScroll.destroy();
  }, []);

  return (
    <>
          <div className="section2">
        <h1>how can we help You?</h1>
      </div>
      <div className="scroll-container">
        <div className="bgtxt">
          <h2>CONTACT US</h2>
        </div>
        <div className="grid-container">
          <div className="map-container">
            <h2 className="heading">Our Location</h2>
            <iframe
              src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d111679.74841934873!2d77.8144012972656!3d30.415937000000007!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x3908d4890d7c1735%3A0x22d3ae324c238e3c!2sUPES!5e1!3m2!1sen!2sin!4v1723889571482!5m2!1sen!2sin"
              width="100%"
              height="90%"
              style={{ border: 0 }}
              allowFullScreen="true"
              loading="lazy"
              referrerPolicy="no-referrer-when-downgrade"
            ></iframe>
          </div>
          <div className="form-container">
            <h2 className="mainHeading">Feel Free to Contact Us</h2>
            <form className="formx" ref={formRef} onSubmit={handleSubmit}>
              <div className="inputGroup">
                <label className="label" htmlFor="firstName">First Name</label>
                <input
                  type="text"
                  name="firstName"
                  id="firstName"
                  className="styled-input"
                  value={formData.firstName}
                  onChange={handleChange}
                />
              </div>
              <div className="inputGroup">
                <label className="label" htmlFor="lastName">Last Name</label>
                <input
                  type="text"
                  name="lastName"
                  id="lastName"
                  className="styled-input"
                  value={formData.lastName}
                  onChange={handleChange}
                />
              </div>
              <div className="inputGroup">
                <label className="label" htmlFor="email">Email</label>
                <input
                  type="email"
                  name="email"
                  id="email"
                  className="styled-input"
                  value={formData.email}
                  onChange={handleChange}
                />
              </div>
              <div className="inputGroup">
                <label className="label" htmlFor="topic">Topic</label>
                <input
                  type="text"
                  name="topic"
                  id="topic"
                  className="styled-input"
                  value={formData.topic}
                  onChange={handleChange}
                />
              </div>
              <div className="inputGroup">
                <label className="label" htmlFor="message">Message</label>
                <textarea
                  name="message"
                  id="message"
                  className="styled-textarea"
                  value={formData.message}
                  onChange={handleChange}
                />
              </div>
              <button type="submit" className="styled-button">Submit</button>
            </form>
            {feedback && <p>{feedback}</p>}
          </div>
        </div>
      </div>
      <HelmetProvider>
        <Helmet>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css"></link>
         </Helmet>
        </HelmetProvider>

      <div class="social-media-container">
  <p class="title">Follow Us</p>
  <ul class="social-media-list">
  <li><a href="#"><i class="fa-brands fa-instagram"></i><span>Instagram</span></a></li>
    <li><a href="#"><i class="fa-brands fa-youtube"></i><span>YouTube</span></a></li>
    <li><a href="#"><i class="fa-brands fa-spotify"></i><span>Spotify</span></a></li>
    <li><a href="#"><i class="fa-brands fa-facebook"></i><span>Facebook</span></a></li>
    <li><a href="#"><i class="fa-brands fa-tiktok"></i><span>TikTok</span></a></li>
    <li><a href="#"><i class="fa-brands fa-twitter"></i><span>Twitter</span></a></li>
    <li><a href="#"><i class="fa-brands fa-snapchat"></i><span>Snapchat</span></a></li>
    <li><a href="#"><i class="fa-brands fa-apple"></i><span>Apple</span></a></li>
  </ul>
</div>

    </>
  );
};

export default ContactContent;
