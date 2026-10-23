import { createRoot } from 'react-dom/client';
import App from './App';
import './styles.css';

// Error views are deliberately generic: never emit returned content or credentials.
createRoot(document.getElementById('root')!, { onCaughtError: () => {}, onUncaughtError: () => {} }).render(<App />);
