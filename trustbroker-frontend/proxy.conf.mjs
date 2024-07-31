
const backendUrl = process.env.XTB_BACKEND_URL || 'http://localhost:8080'

export default [
	{
		context: [
			'/api',
			'/login',
			'/logout',
			'/oauth2',
			'/userinfo',
			'/realms',
			'/saml2',
			'/.well-known'
		],
		target: backendUrl,
		secure: false
	}
];
