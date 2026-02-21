export default function handler(req: any, res: any) {
  const uptime = process.uptime();
  
  const healthStatus = {
    status: 'ok',
    service: 'scan-before-clone-api',
    uptime: `${Math.floor(uptime)}s`,
    timestamp: new Date().toISOString(),
    environment: process.env.VERCEL_ENV || 'development'
  };

  // CORS headers
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  res.status(200).json(healthStatus);
}
