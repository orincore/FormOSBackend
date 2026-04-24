const Tesseract = require('tesseract.js');
const path = require('path');
const fs = require('fs').promises;
const pdfParse = require('pdf-parse');
const { fromPath } = require('pdf2pic');

class OCRService {
  async extractText(filePath) {
    try {
      const ext = path.extname(filePath).toLowerCase();
      
      if (ext === '.pdf') {
        return await this.extractTextFromPDF(filePath);
      } else {
        return await this.extractTextFromImage(filePath);
      }
    } catch (error) {
      console.error('OCR extraction error:', error);
      throw new Error('Failed to extract text from document');
    }
  }

  async extractTextFromImage(imagePath) {
    const result = await Tesseract.recognize(imagePath, 'eng', {
      logger: (m) => console.log(m)
    });
    return result.data.text;
  }

  async extractTextFromPDF(pdfPath) {
    try {
      // First, try to extract text directly from PDF
      const dataBuffer = await fs.readFile(pdfPath);
      const pdfData = await pdfParse(dataBuffer);
      
      if (pdfData.text && pdfData.text.trim().length > 50) {
        console.log('✅ Extracted text directly from PDF');
        return pdfData.text;
      }

      // If PDF is image-based (scanned), convert to images and use OCR
      console.log('📄 PDF appears to be image-based, using OCR...');
      return await this.extractTextFromScannedPDF(pdfPath);
    } catch (error) {
      console.error('PDF extraction error:', error);
      // If PDF parsing fails, try OCR on scanned PDF
      console.log('📄 Trying OCR on PDF...');
      try {
        return await this.extractTextFromScannedPDF(pdfPath);
      } catch (ocrError) {
        console.error('PDF OCR error:', ocrError);
        return 'Failed to extract text from PDF. The file may be encrypted or corrupted.';
      }
    }
  }

  async extractTextFromScannedPDF(pdfPath) {
    try {
      const options = {
        density: 300,
        saveFilename: 'pdf-page',
        savePath: path.dirname(pdfPath),
        format: 'png',
        width: 2000,
        height: 2000
      };

      const convert = fromPath(pdfPath, options);
      
      // Convert first 3 pages (to avoid processing huge PDFs)
      const pageLimit = 3;
      let allText = '';

      for (let i = 1; i <= pageLimit; i++) {
        try {
          const pageImage = await convert(i, { responseType: 'image' });
          
          if (pageImage && pageImage.path) {
            const result = await Tesseract.recognize(pageImage.path, 'eng');
            allText += result.data.text + '\n\n';
            
            // Clean up temporary image
            await fs.unlink(pageImage.path).catch(() => {});
          }
        } catch (pageError) {
          // Page doesn't exist or error, stop processing
          break;
        }
      }

      return allText.trim() || 'No text could be extracted from PDF';
    } catch (error) {
      console.error('Scanned PDF OCR error:', error);
      return 'PDF processing failed. Please try uploading as an image.';
    }
  }

  parseStructuredData(text) {
    const data = {};

    // If text is empty or error message, return empty data
    if (!text || text.length < 10 || text.includes('processing failed')) {
      return data;
    }

    // Extract Aadhaar number (12 digits)
    const aadhaarMatch = text.match(/\b\d{4}\s?\d{4}\s?\d{4}\b/);
    if (aadhaarMatch) {
      data.aadhaarNumber = aadhaarMatch[0].replace(/\s/g, '');
    }

    // Extract PAN number (ABCDE1234F format)
    const panMatch = text.match(/\b[A-Z]{5}\d{4}[A-Z]\b/);
    if (panMatch) {
      data.panNumber = panMatch[0];
    }

    // Extract name (common patterns)
    const nameMatch = text.match(/(?:Name|NAME)[:\s]+([A-Z][a-z]+(?:\s[A-Z][a-z]+)*)/);
    if (nameMatch) {
      data.fullName = nameMatch[1];
    }

    // Extract DOB (various formats)
    const dobMatch = text.match(/(?:DOB|Date of Birth|Birth)[:\s]+(\d{2}[-\/]\d{2}[-\/]\d{4})/);
    if (dobMatch) {
      data.dateOfBirth = dobMatch[1];
    }

    // Extract phone number
    const phoneMatch = text.match(/(?:Phone|Mobile|Tel)[:\s]+(\+?\d{10,12})/);
    if (phoneMatch) {
      data.phone = phoneMatch[1];
    }

    // Extract email
    const emailMatch = text.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/);
    if (emailMatch) {
      data.email = emailMatch[0];
    }

    // Extract address (enhanced pattern to capture full address including state and PIN)
    // Try multiple patterns to capture complete address
    let addressMatch = text.match(/(?:Address|ADDRESS)[:\s]+(.+?)(?=\n\n(?:Aadhaar|PAN|DOB|Date)|$)/s);
    if (!addressMatch) {
      // Try alternative pattern for Aadhaar cards
      addressMatch = text.match(/(?:Address|ADDRESS)[:\s]+(.+?)(?=DIST:|Aadhaar|$)/si);
    }
    if (!addressMatch) {
      // Try to capture address with state and PIN
      addressMatch = text.match(/(?:Address|ADDRESS)[:\s]+(.+?(?:Maharashtra|Gujarat|Karnataka|Tamil Nadu|Delhi|Rajasthan|Uttar Pradesh|Madhya Pradesh|West Bengal|Punjab|Haryana|Bihar|Odisha|Kerala|Assam|Jharkhand|Chhattisgarh|Goa|Uttarakhand|Himachal Pradesh|Tripura|Meghalaya|Manipur|Nagaland|Arunachal Pradesh|Mizoram|Sikkim|Telangana|Andhra Pradesh|MH|GJ|KA|TN|DL|RJ|UP|MP|WB|PB|HR|BR|OR|KL|AS|JH|CG|GA|UK|HP|TR|ML|MN|NL|AR|MZ|SK|TS|AP)\s*-?\s*\d{5,6})/si);
    }
    if (addressMatch) {
      let address = addressMatch[1].trim();
      // Clean up: remove Aadhaar numbers, VID, and other non-address text
      address = address.replace(/\b\d{4}\s?\d{4}\s?\d{4}\b/g, ''); // Remove Aadhaar numbers
      address = address.replace(/VID\s*:\s*\d+/gi, ''); // Remove VID
      address = address.replace(/Details\s+as\s+on:/gi, ''); // Remove "Details as on:"
      address = address.replace(/\s{2,}/g, ' '); // Replace multiple spaces with single space
      data.address = address.trim();
    } else {
      // Last resort: try to find address between common markers
      const addressLines = text.match(/(?:MUKUMD|House|Flat|Plot|Building|Street|Road|Lane|Village).+?(?:Maharashtra|Gujarat|Karnataka|Tamil Nadu|Delhi|Rajasthan|Uttar Pradesh|Madhya Pradesh|West Bengal|Punjab|Haryana|Bihar|Odisha|Kerala|Assam|Jharkhand|Chhattisgarh|Goa|Uttarakhand|Himachal Pradesh|MH|GJ|KA|TN|DL|RJ|UP|MP|WB|PB|HR|BR|OR|KL|AS|JH|CG|GA|UK|HP|TR|ML|MN|NL|AR|MZ|SK|TS|AP)\s*-?\s*\d{5,6}/si);
      if (addressLines) {
        let address = addressLines[0].trim();
        // Clean up
        address = address.replace(/\b\d{4}\s?\d{4}\s?\d{4}\b/g, '');
        address = address.replace(/VID\s*:\s*\d+/gi, '');
        address = address.replace(/\s{2,}/g, ' ');
        data.address = address.trim();
      }
    }

    return data;
  }
}

module.exports = new OCRService();
