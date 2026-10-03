# PhishLens – Smishing & QR Analyzer (Vercel)
index.html       mobile web app (camera, QR via jsQR, OCR via Tesseract.js)
api/analyze.py   Python serverless API (rules + ML, stdlib only)
api/_core.py     analyzer logic      api/_model.json  trained model
training/        dataset, training script (python smishing_analyzer.py train), webcam script

Deploy: push this folder to GitHub -> vercel.com/new -> Import -> Deploy (no settings needed).
Or: npm i -g vercel && vercel --prod
Test API: curl -X POST https://YOUR-APP.vercel.app/api/analyze -H "Content-Type: application/json" -d '{"text":"URGENT verify your PIN http://bit.ly/x"}'
Retrain: cd training && python smishing_analyzer.py train, then copy model.json to api/_model.json.
