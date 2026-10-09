const NetworkSpeed = require('network-speed');
const testNetworkSpeed = new NetworkSpeed();

// فحص سرعة التحميل باستخدام ملف اختبار حقيقي من خادمك
async function getDownloadSpeed() {
  const baseUrl = 'http://localhost:3000/test-file.zip'; // ملف حجمه 5MB مثلاً على خادمك
  const fileSizeInBytes = 5000000;
  const speed = await testNetworkSpeed.checkDownloadSpeed(baseUrl, fileSizeInBytes);
  console.log(speed); // سيعيد النتيجة بدقة مثل: { mbps: '45.20', kbps: '46284.80' }
}
