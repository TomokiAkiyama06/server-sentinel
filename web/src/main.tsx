import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createDashboardServices } from './shared/services';
import './style.css';

// The Main Server serves this bundle only to a signed-in session (S5-2) and
// authorizes every API request itself; this provider decides nothing.
const services = createDashboardServices(window.location.origin);
const root = document.getElementById('root');
if (root) createRoot(root).render(<App services={services} />);
