import React from 'react';
import "./footer.css";
import 'boxicons';

const Footer = () => {
  return (
    
    <footer>
      <div className="containerx">
        <div className="content_footer">
          <div className="profil">
            <div className="logo_area">
              <img src="/ip.svg" alt="OWASPGuard logo" />
              <span className="logo_name">OWASPGuard Security Analyzer</span>
            </div>
            <div className="desc_area">
            <p>OWASPGuard is a local-first static application security tool that helps you enforce OWASP Top 10 practices across your code, dependencies, and configuration without sending data to the cloud.</p>
            </div>
            <div className="social_media">
            <box-icon type='logo' name='facebook-square' size='md' ></box-icon>
            <box-icon type='logo' name='twitter' size='md'></box-icon>
            <box-icon type='logo' name='instagram' size='md'></box-icon>
            <box-icon type='logo' name='linkedin-square'size='md'></box-icon>
            <box-icon type='logo' name='github' size='md'></box-icon>
            </div>
          </div>
          <div className="service_area">
            <ul className="service_header">
              <li className="service_name">We Provide</li>
              <li><a href='#'>Static code analysis (SAST)</a></li>
              <li><a href='#'>Dependency vulnerability scanning (SCA)</a></li>
              <li><a href='#'>Secrets &amp; configuration checks</a></li>
              <li><a href='#'>OWASP Top 10 reporting</a></li>
            </ul>
            <ul className="service_header">
              <li className="service_name">Partners</li>
              <li><a href='#'>Google API</a></li>
              <li><a href='#'>Rapid X API</a></li>
              <li><a href='#'>Google Maps API</a></li>
              <li><a href='#'>News Org API</a></li>
            </ul>
            <ul className="service_header">
            <li className="service_name">Resources</li>
              <li><a href='#'>Blog</a></li>
              <li><a href='#'>Case Studies</a></li>
              <li><a href='#'>White Papers</a></li>
              <li><a href='#'>Webinars</a></li>
              </ul>
          </div>
        </div>
        <hr></hr>

        <div className="footer_bottom">
          <div className="copy_right">
          <box-icon name='copyright' ></box-icon>
            <span>2024 minorproject</span>
          </div>
          <div className="tou">
            <a href=''>Term of Use</a>
            <a href=''>Privacy Policy</a>
            <a href=''>Cookies</a>
          </div>
        </div>
      </div>
    </footer>
  )
}

export default Footer;