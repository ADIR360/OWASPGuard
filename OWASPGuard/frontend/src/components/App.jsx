import Home from './pages/home/home'
import About from './pages/about/About'
import Legal from './pages/legal/Legal'
import Contact from './pages/contact/Contact'
import Login from './pages/login/login'
import Vulnerability from './pages/vulnerability/Vulnerability'
import CustomCursor from './CustomCursor'

import {
  BrowserRouter,
  Routes,
  Route,
} from 'react-router-dom'

const App = () => {
  return (
    <>
      <CustomCursor />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/legal" element={<Legal />} />
          <Route path="/about" element={<About />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/login" element={<Login />} />
          <Route path="/vulnerabilities" element={<Vulnerability />} />
        </Routes>
      </BrowserRouter>
    </>
  )
}

export default App
