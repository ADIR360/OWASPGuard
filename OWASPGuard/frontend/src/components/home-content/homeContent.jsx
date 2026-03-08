import React,{ useEffect } from "react";
import "./homeContent.css";

import arrow from '../img/arrow_upward.svg';

import img1 from '../img/rd.svg';
import img2 from '../img/webby.svg';
import img3 from '../img/pmi.svg';
import img4 from '../img/wf.svg';
import img5 from '../img/adweek.svg';
import img6 from '../img/forbes.svg';

import imgpg2 from '../img/pg21.webp';
import Video from "../img/vip.mp4";
import img1pg4 from '../img/grid1.jpg';
import img2pg5 from '../img/grid2.jpg';

// Slider Images
import slide1 from '../img/slide1.webp';
import slide2 from '../img/slide2.webp';

import slide21 from '../img/slide21.webp';
import slide22 from '../img/slide22.jpg';
import slide23 from '../img/slide23.jpg';
import slide24 from '../img/slide24.jpg';

import slide31 from '../img/slide31.webp';
import slide32 from '../img/slide32.png';
import slide33 from '../img/slide33.jpg';


import Aos from "aos";
import 'aos/dist/aos.css'

//Smooth Scroll Animation
import LocomotiveScroll from 'locomotive-scroll';
const locomotiveScroll = new LocomotiveScroll();

import "../assets/animations/locomotive-scroll.css";

// import { Helmet } from "react-helmet";
import { Helmet, HelmetProvider } from 'react-helmet-async';
import { Swiper, SwiperSlide } from 'swiper/react';
import 'swiper/css';
import 'swiper/css/pagination';
import 'swiper/css/navigation';
import { Autoplay} from 'swiper/modules';
import { preLoaderAnim } from "../assets/animations";


const PreLoader = () => {
  useEffect(() => {
    preLoaderAnim();
      }, []);
  return (
    <div className="preloader">
      <div className="texts-container">
        <span>| OWASPGuard </span>
        <span>&nbsp;| Major Project |&nbsp; </span>
        <span> by Arush |</span>
      </div>
    </div>
  );
};


const AOSs = () =>{
  useEffect(() => {
    Aos.init({ duration: 1000 });
  }, []);
}

// ------------------------BACK TO TOP------------------------
const ScrollToTop = () => {
  useEffect(() => {
    const backToTopButton = document.querySelector('.backtotop');
  // Initially hide the button
  backToTopButton.style.display = 'none';
    const handleScroll = () => {
      if (window.scrollY > 300) {
        backToTopButton.style.display = 'block';
      } else {
        backToTopButton.style.display = 'none';
      }
    };

    const handleClick = () => {
      window.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    };

    backToTopButton.addEventListener('click', handleClick);
    window.addEventListener('scroll', handleScroll);

    return () => {
      backToTopButton.removeEventListener('click', handleClick);
      window.removeEventListener('scroll', handleScroll);
    };
  }, []);
  return (
    <div className="backtotop"><img className="arrow" src={arrow} alt="" /></div>
  );
};
// ------------------------BACK TO TOP------------------------

const HomeContent = () => {
  
  useEffect(() => {
    const scroll = new LocomotiveScroll({
      el: document.querySelector('.main'),
      smooth: true,
      multiplier: 0.5,
      lerp: 0.1,
    });
  }, []);

  return (
    <>
      <PreLoader/>
      <ScrollToTop></ScrollToTop>
      <AOSs/>

        <HelmetProvider>
        <Helmet>
          {/* <script src="./script.js"></script> */}
          <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet"></link>
          <script src="https://cdn.jsdelivr.net/npm/locomotive-scroll@3.5.4/dist/locomotive-scroll.js"></script>
          <link href="https://cdn.jsdelivr.net/npm/locomotive-scroll@3.5.4/dist/locomotive-scroll.css" rel="stylesheet" />
          <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js" integrity="sha512-7eHRwcbYkK4d9g/6tD/mhkf++eoTHwpNM9woBxtPUBWm67zeAfFC+HrdoE2GanKeocly/VxeLvIqwvCdk7qScg==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/ScrollTrigger.min.js" integrity="sha512-onMTRKJBKz8M1TnqqDuGBlowlH0ohFzMXYRNebz+yOcc5TQr/zAKsthzhuv0hiyUKEiQEQXEynnXCvNTOk50dg==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
        </Helmet>
        </HelmetProvider>
    

      <div className="main">

        {/*-------------Page-1------------- */}
        <div className="page1">
          <h1 data-scroll data-scroll-speed="0.1"> IP VULNERABILTY
          <br></br>TRACKER</h1>
          <p data-scroll data-scroll-speed="0.1" >The IP analysis system is designed to be versatile, with a wide range of applications across various industries and sectors. Its ability to detect and mitigate network security threats in real-time makes it an invaluable tool for any organization that relies on digital infrastructure.
          </p>
          <div data-scroll data-scroll-speed="0.1" id="trio-buttons">
            <h2> Information </h2>
            <h2> Data </h2>
            <h2> Vulnerablity </h2>
          </div>


          <div className="moving-div" >
            <div id="blur-left"></div>

            <div className="move">
              <img src={img1} alt="" />
              <img src={img2} alt="" />
              <img src={img3} alt="" />
              <img src={img4} alt="" />
              <img src={img5} alt="" />
              <img src={img6} alt="" />
              <img src={img3} alt="" />
              <img src={img4} alt="" />
            </div>

            <div className="move">
              <img loading="lazy" src={img1} alt="" />
              <img loading="lazy" src={img2} alt="" />
              <img loading="lazy" src={img3} alt="" />
              <img loading="lazy" src={img4} alt="" />
              <img loading="lazy" src={img5} alt="" />
              <img loading="lazy" src={img6} alt="" />
              <img loading="lazy" src={img3} alt="" />
              <img loading="lazy" src={img4} alt="" />
            </div>
            <div id="blur-right"></div>
          </div>
        </div>


        {/*-------------Page-2------------- */}
        <div className="page2">
        <div className= "linear-gradient">
        {/* <h6 > W<span>EB </span> 
          <br />TRACKER</h6> */}
          <div className="boxx">
            <div className="inner-box">
              <h1 data-scroll data-scroll-speed="0.1"> Introducing GUI PLATFORM</h1>
              <div className="contentz">
              <h2 data-scroll data-scroll-speed="0.1" > WEB Vulnerabily Detection</h2>
              <h3 data-scroll data-scroll-speed="0.1" >Now Hands ON</h3>  
              </div>
              <div data-scroll data-scroll-speed="0.1" className="image-containerx">
              <img loading="lazy" className="hover-image" src={imgpg2} alt="" />
              </div>




            </div>
          </div>
        
        <div className="container1">
          <p className="loop-text">WEBHACK GEOLOCATION</p>
          <p className="loop-text">WEBHACK GEOLOCATION</p>
          <p className="loop-text">WEBHACK GEOLOCATION</p>
        </div>
        </div>
        </div>


        {/*-------------Page-3------------- */}
        <div className="page3">
        <div id="gradient"></div>
        <div id="box">
          <div id="video-box" data-scroll data-scroll-speed="0.2">
              <video autoPlay loop muted src={Video} type="video/mp4"/>
            </div>
            <div id="text-box" data-scroll data-scroll-speed="0.2">
                <h2>Real-Time Threat Detection</h2>
                <p>The system's ability to analyse IP traffic as it happens provides a powerful defence mechanism, allowing immediate identification and response to potential security threats. This real-time capability ensures that malicious activities, such as DDoS attacks or unauthorized access attempts, are detected and mitigated before they can cause significant damage.</p>
              </div>
          </div>
        </div>

        {/*-------------Page-4------------- */}
        <div className="page4">
          <div className="box">
            <div className="image-container image">
              <img loading="lazy" className="hover-image" src={img1pg4} alt="" />
            </div>

            <div className="text-content">
              <h1>Informatics</h1>
              <p>The IP Vulnerability Tracker is an essential tool for cybersecurity, providing real-time monitoring and automated scanning of IP addresses to detect vulnerabilities. It delivers detailed risk analysis, integrates with SIEM systems, and offers threat intelligence updates. Stay proactive in identifying and mitigating risks to enhance your network security.
                </p></div>
            </div>
        </div>

        {/*-------------Page-5------------- */}
        <div className="page5">
          <div className="box">
            <div className="image-container image">
              <img loading="lazy" className="hover-image" src={img2pg5} alt="" />
            </div>
            <div className="text-content">
              <h1>About</h1>
              <p>Our platform is designed to be user-friendly, with a simple and intuitive interface that allows users to easily navigate and access the information they need. The system provides detailed reports and alerts, enabling users to quickly identify and respond to potential threats. With real-time monitoring and automated scanning, the IP Vulnerability Tracker is a powerful tool for enhancing network security.
                </p></div>
            </div>
        </div>


        {/*-------------Page-6------------- */}
        <div className="page6">

        <h1 data-scroll data-scroll-speed="0.01" >Get in touch.</h1>        
      <Swiper
      // data-scroll data-scroll-speed="0.2"
        spaceBetween={30}
        centeredSlides={true}
        autoplay={{
          delay: 2000,
          disableOnInteraction: false,
        }}
        pagination={{
          clickable: true,
        }}
        modules={[Autoplay]}
        className="mySwiper"
        >
      
        <SwiperSlide>
          <div className="slidess">
          <img src={slide1} alt="" />
          <img src={slide2} alt="" />
          </div>
        </SwiperSlide>
        <SwiperSlide>
          <div className="slides">
          <img src={slide21} alt="" />
          <img src={slide22} alt="" />
          <img src={slide23} alt="" />
          <img src={slide24} alt="" />
          </div>
        </SwiperSlide>
        <SwiperSlide>
          <div className="slidesx">
          <img src={slide31} alt="" />
          <img src={slide32} alt="" />
          <img src={slide33} alt="" />

          </div>
        </SwiperSlide>

      </Swiper>



        </div> 
      </div>
    </>
  );
};

export default HomeContent;




// .image {
//   filter: grayscale();
//   transition: all ease-in-out;
//   transition-duration: 500ms;

// }

// .image-container:hover .image {
//   filter: none;
// }