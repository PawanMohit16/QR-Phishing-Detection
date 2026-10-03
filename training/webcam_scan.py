"""Laptop webcam scanner. Keep smishing_analyzer.py in the same folder.
Keys: s = OCR the current frame | q = quit. QR codes are decoded automatically.
Install: pip install opencv-python pytesseract   (+ Tesseract OCR program)
"""
import cv2, pytesseract
from smishing_analyzer import report

cap = cv2.VideoCapture(0)          # 0 = built-in laptop camera (try 1 if it fails)
qr = cv2.QRCodeDetector()
last = ""
print("Camera on. Show a QR code, or press 's' to read text. 'q' quits.")

while cap.isOpened():
    ok, frame = cap.read()
    if not ok:
        break
    data, pts, _ = qr.detectAndDecode(frame)
    if data and data != last:                       # new QR found
        last = data
        report("QR code opens: " + data)
    cv2.putText(frame, "s = OCR text | q = quit", (10, 25),
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)
    cv2.imshow("PhishLens webcam", frame)
    key = cv2.waitKey(1) & 0xFF
    if key == ord("s"):
        text = pytesseract.image_to_string(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)).strip()
        if text:
            report(text)
        else:
            print("No text found. Hold the screen steady and closer.")
    elif key == ord("q"):
        break

cap.release()
cv2.destroyAllWindows()
