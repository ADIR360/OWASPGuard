import React from 'react';
import './About.css';  // Page-specific styles for the About page
import defaultAvatar from '../img/webby.svg';

function Content() {
  return (
    <div className="about-page-container">
      <div className="about-container">
        <h3 id='back'>ABOUT</h3>
        <div className='bxx'></div>
        <div className='bx'></div>
        <h3 id='back2'>OWASPGuard</h3>
        <div className="content">
          <h1 className="top-heading">About OWASPGuard</h1>
        </div>
      </div>

      <div className='about-content'>
        <div className='about-profile'>
          <main className="about-main">
            <div className="about-top">
              <h1>What OWASPGuard does</h1>
              <p>
                OWASPGuard is an offline-first static application security testing (SAST) and software
                composition analysis (SCA) tool. It scans source code, dependencies, and configuration
                files, then maps every finding to the OWASP Top 10 so you can reason about real risk
                instead of raw regex matches.
              </p>
            </div>
          </main>
        </div>

        <div className='about-profile'>
          <main className="about-main">
            <div className="about-top">
              <h1>How the engine works</h1>
              <p>
                Under the hood a scan is orchestrated in phases: static code analysis (Python and
                JavaScript), dependency scanning via a local CVE database, and configuration &amp; secrets
                checks. A rule engine, AST-based context scanner, taint analysis, entropy checks, and
                OWASP-specific scanners all contribute findings that are then normalized, scored, and
                grouped by OWASP category.
              </p>
            </div>
          </main>
        </div>

        <div className='about-profile'>
          <main className="about-main">
            <div className="about-top">
              <h1>Models and detection strategy</h1>
              <p>
                OWASPGuard combines a Hugging Face transformer classifier for rich semantic
                understanding of code with a tiny LightGBM model optimized for offline prediction.
                The transformer (via the HfVulnerabilityClassifier) is used when available to
                provide high-quality predictions, while the gradient-boosted tree model offers a
                fast, ~500KB fallback that still reaches strong accuracy on common vulnerability
                patterns.
              </p>
            </div>
          </main>
        </div>

        <div className='about-profile'>
          <main className="about-main">
            <div className="about-top">
              <h1>Design goals</h1>
              <p>
                Every part of OWASPGuard is built to be transparent, explainable, and safe to run on
                sensitive codebases. Findings include code snippets, OWASP mappings, ML confidence,
                and remediation text, and all analysis can run completely offline so your source code
                never leaves your environment.
              </p>
            </div>
          </main>
        </div>

        <div className='about-profile'>
          <main className="about-main">
            <div className="about-top">
              <h1>About the developer</h1>
              <p>
                OWASPGuard is designed and maintained by a single developer who owns the entire
                stack—from the rule engine and ML experiments to the FastAPI backend and React
                dashboard. That focus allows the project to evolve quickly while staying true to its
                core mission: making practical, OWASP-aligned security analysis accessible to
                everyday developers.
              </p>
            </div>
          </main>
        </div>
      </div>
    </div>
  );
}

export default Content;
