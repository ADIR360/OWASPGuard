import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './App.css'

import { Navbar } from './components/navbar/Navbar'
import { Footer } from './components/footer/Footer'
import { HomeContent } from './components/home-content/HomeContent'
import { CardSection } from './components/card-content/CardSection'
import { AboutContent } from './components/about-content/AboutContent'
import { VulnerabilityDashboard } from './components/vulnerability-content/VulnerabilityDashboard'
import { ContactForm } from './components/contact-content/ContactForm'
import { LoginPage } from './components/login-content/LoginPage'
import { LegalPage } from './components/legal-content/LegalPage'

function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <Navbar />
        <main className="router-main">
          <Routes>
            <Route
              path="/"
              element={(
                <>
                  <HomeContent />
                  <CardSection />
                </>
              )}
            />
            <Route path="/about" element={<AboutContent />} />
            <Route path="/vulnerabilities" element={<VulnerabilityDashboard />} />
            <Route path="/contact" element={<ContactForm />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/legal" element={<LegalPage />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </BrowserRouter>
  )
}

export default App
