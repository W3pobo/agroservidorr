// static/js/accesibilidad.js - v2.0 con FAB y Menú Flotante
class LectorPantalla {
    constructor() {
        this.panelVisible = false;
        this.audioPlayer = new Audio();
        this.tipografias = ['default', 'google-sans', 'samsung-one', 'sf-pro'];
        
        // Banderas para evitar que el audio se reproduzca múltiples veces
        this.isSpeaking = false;
        this.audioQueue = [];

        this.inicializar();
    }

    inicializar() {
        console.log('🔄 Inicializando Menú de Accesibilidad v2.0 (FAB)...');
        this.crearPanel();
        this.aplicarEstilos();
        this.configurarEventos();
        this.mejorarAccesibilidadElementos();
        this.cargarPreferencias();
    }

    crearPanel() {
        if (document.getElementById('accesibilidad-toggle-fab')) return;

        // 1. Botón flotante principal (FAB)
        const toggleBtn = document.createElement('button');
        toggleBtn.id = 'accesibilidad-toggle-fab';
        toggleBtn.title = 'Abrir panel de accesibilidad (Ctrl+Alt+A)';
        toggleBtn.innerHTML = `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2c2.76 0 5 2.24 5 5s-2.24 5-5 5-5-2.24-5-5 2.24-5 5-5z"/><path d="M19.27 12.9a8.25 8.25 0 0 1-14.54 0"/><path d="M12 12v10"/></svg>`;
        document.body.appendChild(toggleBtn);

        // 2. Panel flotante (Menú)
        const panel = document.createElement('div');
        panel.id = 'accesibilidad-menu-flotante';
        // No usamos cabecera, es un menú directo.
        panel.innerHTML = `
            <div class="panel-content-flotante">
                <!-- Opción: Contraste -->
                <div class="accesibilidad-opcion">
                    <div class="opcion-label">
                        <span class="opcion-icono">◑</span>
                        <span>Contraste</span>
                    </div>
                    <div class="opcion-control">
                        <select id="contraste-select" class="accesibilidad-select">
                            <option value="none">Ninguno</option>
                            <option value="high">Alto</option>
                            <option value="very-high">Muy Alto</option>
                            <option value="inverted">Invertido</option>
                            <option value="yellow-black">Amarillo/Negro</option>
                        </select>
                    </div>
                </div>

                <!-- Opción: Tamaño de Fuente -->
                <div class="accesibilidad-opcion">
                    <div class="opcion-label">
                        <span class="opcion-icono">T</span>
                        <span>Fuente</span>
                    </div>
                    <div class="opcion-control font-size-control">
                        <button id="font-decrease-btn" class="font-btn" title="Disminuir fuente">-</button>
                        <span id="tamanio-fuente-estado">100%</span>
                        <button id="font-increase-btn" class="font-btn" title="Aumentar fuente">+</button>
                    </div>
                </div>

                <!-- Opción: Tipografía -->
                <div class="accesibilidad-opcion">
                    <div class="opcion-label">
                        <span class="opcion-icono">Aa</span>
                        <span>Tipografía</span>
                    </div>
                    <div class="opcion-control">
                        <button id="tipografia-btn" class="accesibilidad-btn-toggle">
                            <span id="tipografia-estado">Default</span>
                        </button>
                    </div>
                </div>

                <!-- Opción: Tema -->
                <div class="accesibilidad-opcion">
                    <div class="opcion-label">
                        <span class="opcion-icono">☀️/🌙</span>
                        <span>Tema</span>
                    </div>
                    <div class="opcion-control">
                        <button id="theme-btn" class="accesibilidad-btn-toggle">
                            <span id="theme-estado">Claro</span>
                        </button>
                    </div>
                </div>
                
                <!-- Opción: Escala de Grises -->
                <div class="accesibilidad-opcion">
                    <div class="opcion-label">
                        <span class="opcion-icono" style="font-style: normal;">G</span>
                        <span>Grises</span>
                    </div>
                    <div class="opcion-control">
                        <label class="switch">
                          <input type="checkbox" id="grayscale-checkbox">
                          <span class="slider round"></span>
                        </label>
                    </div>
                </div>

                <!-- Opción: Cursor -->
                <div class="accesibilidad-opcion">
                    <div class="opcion-label">
                        <span class="opcion-icono">🖱️</span>
                        <span>Cursor</span>
                    </div>
                    <div class="opcion-control">
                        <button id="cursor-btn" class="accesibilidad-btn-toggle">
                            <span id="cursor-estado">Normal</span>
                        </button>
                    </div>
                </div>

                <!-- Opción: Lector de Pantalla -->
                <div class="accesibilidad-opcion">
                    <div class="opcion-label">
                        <span class="opcion-icono">🔊</span>
                        <span>Lector</span>
                    </div>
                    <div class="opcion-control">
                        <button id="leer-seleccion-btn" class="accesibilidad-btn-simple">Leer Selección</button>
                    </div>
                </div>
            </div>
            <!-- Notificador de mensajes -->
            <div id="accesibilidad-notif"></div>
        `;
        document.body.appendChild(panel);
    }

    aplicarEstilos() {
        const estilos = `
            /* --- Botón Flotante (FAB) --- */
            #accesibilidad-toggle-fab {
                position: fixed;
                bottom: 25px;
                right: 25px;
                z-index: 1002;
                width: 60px;
                height: 60px;
                border-radius: 50%;
                cursor: pointer;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
                display: flex;
                justify-content: center;
                align-items: center;
                transition: all 0.3s ease;
                
                /* Estilo Blur Claro (de estilo5.css nav) */
                background: rgba(255, 255, 255, 0.6);
                backdrop-filter: blur(12px);
                border: 1px solid rgba(0, 0, 0, 0.08);
                color: #333;
            }
            #accesibilidad-toggle-fab svg {
                transition: transform 0.3s ease;
            }
            #accesibilidad-toggle-fab.active svg {
                transform: rotate(45deg);
            }
            #accesibilidad-toggle-fab:hover { 
                transform: scale(1.05);
                box-shadow: 0 6px 16px rgba(0, 0, 0, 0.25);
            }
            
            /* Estilo FAB Dark Mode (de estilo5.css nav) */
            html.dark-mode #accesibilidad-toggle-fab {
                background: rgba(24, 26, 27, 0.65);
                border: 1px solid rgba(255, 255, 255, 0.1);
                color: #f5f5f7;
            }

            /* --- Menú Flotante --- */
            #accesibilidad-menu-flotante {
                position: fixed;
                bottom: 95px; /* 60px del FAB + 25px margen + 10px espacio */
                right: 25px;
                width: 330px;
                z-index: 1001;
                
                /* Estilo Blur Claro (de estilo5.css .container) */
                background: rgba(255, 255, 255, 0.8);
                backdrop-filter: blur(14px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                border-radius: 18px;
                
                /* Oculto por defecto */
                opacity: 0;
                visibility: hidden;
                transform: translateY(20px);
                transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
                overflow: hidden; /* Para que el notificador quede dentro */
            }
            #accesibilidad-menu-flotante.active {
                opacity: 1;
                visibility: visible;
                transform: translateY(0);
            }

            /* Estilo Menú Flotante Dark Mode (de estilo5.css .container) */
            html.dark-mode #accesibilidad-menu-flotante {
                background: rgba(24, 26, 27, 0.72);
                backdrop-filter: blur(18px);
                border: 1.5px solid rgba(0,230,176,0.13);
                box-shadow: 0 8px 32px rgba(0,230,176,0.10);
                color: #f5f5f7;
            }

            .panel-content-flotante { 
                padding: 10px; 
                display: flex;
                flex-direction: column;
                gap: 5px;
            }

            .accesibilidad-opcion {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 12px 15px;
                border-radius: 10px;
                transition: background-color 0.2s ease;
            }
            html:not(.dark-mode) .accesibilidad-opcion:hover {
                background-color: rgba(0,0,0,0.05);
            }
            html.dark-mode .accesibilidad-opcion:hover {
                background-color: rgba(255,255,255,0.08);
            }
            
            .opcion-label { display: flex; align-items: center; gap: 15px; font-weight: 500; font-size: 0.95em; }
            .opcion-icono { font-size: 1.3em; width: 25px; text-align: center; }
            .opcion-control { display: flex; align-items: center; gap: 8px; }

            /* Estilos para controles (adaptados) */
            .accesibilidad-select {
                padding: 6px 10px;
                border-radius: 5px;
                border: 1px solid #ced4da;
                background-color: #fff;
            }
            .font-size-control span { font-weight: bold; width: 40px; text-align: center; }
            .font-btn {
                width: 28px; height: 28px;
                border-radius: 50%;
                border: 1px solid #ced4da;
                background-color: #fff;
                font-weight: bold;
                cursor: pointer;
            }
            .font-btn:hover { background-color: #e9ecef; }
            
            .accesibilidad-btn-toggle {
                padding: 6px 12px;
                border-radius: 20px;
                border: 1px solid #007bff;
                background-color: #fff;
                color: #007bff;
                cursor: pointer;
                min-width: 80px;
                text-align: center;
                font-size: 0.9em;
            }
            .accesibilidad-btn-toggle:hover { background-color: #e7f3ff; }
            
            .accesibilidad-btn-simple {
                padding: 6px 12px;
                border-radius: 5px;
                border: none;
                background-color: #28a745;
                color: white;
                cursor: pointer;
                font-size: 0.9em;
            }
            .accesibilidad-btn-simple:hover { background-color: #218838; }

            /* Dark Mode para Controles */
            html.dark-mode .accesibilidad-select, 
            html.dark-mode .font-btn { 
                background-color: #495057; 
                color: #f8f9fa; 
                border-color: #6c757d; 
            }
            html.dark-mode .accesibilidad-btn-toggle { 
                background-color: transparent; 
                color: #00e6b0; 
                border-color: #00e6b0; 
            }
            html.dark-mode .accesibilidad-btn-toggle:hover {
                background-color: rgba(0, 230, 176, 0.1);
            }

            /* Switch para Grayscale */
            .switch { position: relative; display: inline-block; width: 44px; height: 24px; }
            .switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; }
            .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .4s; }
            input:checked + .slider { background-color: #28a745; }
            html.dark-mode input:checked + .slider { background-color: #00e6b0; }
            input:checked + .slider:before { transform: translateX(20px); }
            .slider.round { border-radius: 24px; }
            .slider.round:before { border-radius: 50%; }

            /* Notificador de Mensajes */
            #accesibilidad-notif {
                position: absolute;
                bottom: 0;
                left: 0;
                width: 100%;
                padding: 10px;
                text-align: center;
                font-size: 0.9em;
                color: white;
                background-color: #007bff;
                opacity: 0;
                visibility: hidden;
                transition: opacity 0.3s, visibility 0.3s;
            }
            #accesibilidad-notif.show {
                opacity: 1;
                visibility: visible;
            }
            #accesibilidad-notif.error { background-color: #dc3545; }
            #accesibilidad-notif.success { background-color: #28a745; }

            /* Clases de accesibilidad (sin cambios) */
            .mejor-focus:focus { outline: 3px solid #FF5722 !important; outline-offset: 2px !important; }
            html { transition: filter 0.3s ease, background-color 0.3s, color 0.3s; }
            html.contrast-high { filter: contrast(175%); }
            html.contrast-very-high { filter: contrast(250%) brightness(110%); }
            html.contrast-inverted { filter: invert(100%) hue-rotate(180deg); }
            html.contrast-yellow-black { filter: sepia(100%) hue-rotate(45deg) contrast(150%); }
            html.grayscale { filter: grayscale(100%); }
            .cursor-grande, .cursor-grande * { cursor: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='32' height='32' style='font-size: 32px;'><text y='32'>👆</text></svg>"), auto !important; }
            .cursor-muy-grande, .cursor-muy-grande * { cursor: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='48' height='48' style='font-size: 48px;'><text y='48'>👆</text></svg>"), auto !important; }
        `;
        const style = document.createElement('style');
        style.textContent = estilos;
        document.head.appendChild(style);
    }

    configurarEventos() {
        const toggleBtn = document.getElementById('accesibilidad-toggle-fab');
        const menu = document.getElementById('accesibilidad-menu-flotante');

        toggleBtn.addEventListener('click', (e) => {
            e.stopPropagation(); // Evita que el click se propague al documento
            this.togglePanel();
        });
        
        // Controles del panel
        document.getElementById('contraste-select').addEventListener('change', (e) => this.aplicarContraste(e.target.value));
        document.getElementById('font-decrease-btn').addEventListener('click', () => this.ajustarTamanioFuente('decrease'));
        document.getElementById('font-increase-btn').addEventListener('click', () => this.ajustarTamanioFuente('increase'));
        document.getElementById('tipografia-btn').addEventListener('click', () => this.ciclarTipografia());
        document.getElementById('theme-btn').addEventListener('click', () => this.toggleTheme());
        document.getElementById('grayscale-checkbox').addEventListener('change', (e) => this.toggleGrayscale(e.target.checked));
        document.getElementById('cursor-btn').addEventListener('click', () => this.ciclarTamanioCursor());
        document.getElementById('leer-seleccion-btn').addEventListener('click', () => this.leerTextoSeleccionado());

        // Atajos de teclado y cierre
        document.addEventListener('keydown', (e) => {
            if (e.key === "Escape" && this.panelVisible) this.togglePanel();
            if (e.ctrlKey && e.altKey && e.key === 'a') this.togglePanel();
        });

        // Clic fuera del menú para cerrar
        document.addEventListener('click', (e) => {
            if (!this.panelVisible) return;
            if (!menu.contains(e.target) && !toggleBtn.contains(e.target)) {
                this.togglePanel();
            }
        });

        // Detener audio al cambiar de página
        window.addEventListener('beforeunload', () => {
            this.audioPlayer.pause();
            this.isSpeaking = false;
        });
    }

    togglePanel() {
        const panel = document.getElementById('accesibilidad-menu-flotante');
        const toggleBtn = document.getElementById('accesibilidad-toggle-fab');
        
        this.panelVisible = !this.panelVisible;
        panel.classList.toggle('active', this.panelVisible);
        toggleBtn.classList.toggle('active', this.panelVisible);
    }

    // --- Métodos de actualización y aplicación (sin cambios de lógica) ---

    aplicarContraste(tipo) {
        const html = document.documentElement;
        html.className = html.className.replace(/\bcontrast-\S+/g, '');
        if (tipo !== 'none') {
            html.classList.add(`contrast-${tipo}`);
        }
        localStorage.setItem('contraste', tipo);
        document.getElementById('contraste-select').value = tipo;
    }

    ajustarTamanioFuente(accion) {
        let tamanioActual = parseInt(localStorage.getItem('tamanioFuente') || 100);
        if (accion === 'increase') {
            tamanioActual = Math.min(150, tamanioActual + 10);
        } else {
            tamanioActual = Math.max(80, tamanioActual - 10);
        }
        document.documentElement.style.fontSize = `${tamanioActual}%`;
        localStorage.setItem('tamanioFuente', tamanioActual);
        document.getElementById('tamanio-fuente-estado').textContent = `${tamanioActual}%`;
    }

    ciclarTipografia() {
        const html = document.documentElement;
        const actualClass = Array.from(html.classList).find(c => c.startsWith('font-'));
        const actualFont = actualClass ? actualClass.replace('font-', '') : 'default';
        const nextIndex = (this.tipografias.indexOf(actualFont) + 1) % this.tipografias.length;
        const nextFont = this.tipografias[nextIndex];

        this.tipografias.forEach(font => html.classList.remove(`font-${font}`));
        if (nextFont !== 'default') {
            html.classList.add(`font-${nextFont}`);
        }
        localStorage.setItem('tipografia', nextFont);
        document.getElementById('tipografia-estado').textContent = nextFont.charAt(0).toUpperCase() + nextFont.slice(1).replace('-', ' ');
    }

    toggleTheme() {
        const html = document.documentElement;
        html.classList.toggle('dark-mode');
        const isDark = html.classList.contains('dark-mode');
        localStorage.setItem('theme', isDark ? 'dark' : 'light');
        document.getElementById('theme-estado').textContent = isDark ? 'Oscuro' : 'Claro';
    }

    toggleGrayscale(activado) {
        document.documentElement.classList.toggle('grayscale', activado);
        localStorage.setItem('grayscale', activado);
        document.getElementById('grayscale-checkbox').checked = activado;
    }

    ciclarTamanioCursor() {
        const body = document.body;
        let estadoActual = localStorage.getItem('cursor') || 'normal';
        let proximoEstado = 'normal';

        if (estadoActual === 'normal') proximoEstado = 'grande';
        else if (estadoActual === 'grande') proximoEstado = 'muy-grande';
        else proximoEstado = 'normal';

        body.classList.remove('cursor-grande', 'cursor-muy-grande');
        if (proximoEstado !== 'normal') {
            body.classList.add(`cursor-${proximoEstado}`);
        }
        localStorage.setItem('cursor', proximoEstado);
        document.getElementById('cursor-estado').textContent = proximoEstado.charAt(0).toUpperCase() + proximoEstado.slice(1);
    }

    // --- Carga de Preferencias (sin cambios de lógica) ---
    
    cargarPreferencias() {
        // Contraste
        const contraste = localStorage.getItem('contraste') || 'none';
        this.aplicarContraste(contraste);

        // Tamaño de fuente
        const tamanio = localStorage.getItem('tamanioFuente') || 100;
        document.documentElement.style.fontSize = `${tamanio}%`;
        document.getElementById('tamanio-fuente-estado').textContent = `${tamanio}%`;

        // Tipografía
        const tipografia = localStorage.getItem('tipografia') || 'default';
        this.tipografias.forEach(font => document.documentElement.classList.remove(`font-${font}`));
        if (tipografia !== 'default') document.documentElement.classList.add(`font-${tipografia}`);
        document.getElementById('tipografia-estado').textContent = tipografia.charAt(0).toUpperCase() + tipografia.slice(1).replace('-', ' ');

        // Tema
        const theme = localStorage.getItem('theme') || 'light';
        if (theme === 'dark') {
            document.documentElement.classList.add('dark-mode');
            document.getElementById('theme-estado').textContent = 'Oscuro';
        }

        // Escala de grises
        const grayscale = localStorage.getItem('grayscale') === 'true';
        this.toggleGrayscale(grayscale);

        // Cursor
        const cursor = localStorage.getItem('cursor') || 'normal';
        document.body.classList.remove('cursor-grande', 'cursor-muy-grande');
        if (cursor !== 'normal') document.body.classList.add(`cursor-${cursor}`);
        document.getElementById('cursor-estado').textContent = cursor.charAt(0).toUpperCase() + cursor.slice(1);
        
        console.log('✅ Preferencias de accesibilidad (v2.0) cargadas');
    }

    // --- Funciones auxiliares ---

    mejorarAccesibilidadElementos() {
        document.querySelectorAll('button, a, input, select, textarea, [tabindex]').forEach(el => {
            el.classList.add('mejor-focus');
        });
    }

    // --- ¡LECTOR DE VOZ ARREGLADO! ---
    async leerTextoSeleccionado() {
        const texto = window.getSelection().toString().trim();
        if (!texto) {
            this.mostrarMensaje('Por favor, selecciona un texto para leer.', 'error');
            return;
        }

        if (this.isSpeaking) {
            this.mostrarMensaje('...Texto añadido a la cola.', 'info');
            this.audioQueue.push(texto);
            return;
        }

        this.isSpeaking = true;
        this.mostrarMensaje('Generando audio...', 'info');

        try {
            const response = await fetch('/texto_a_voz', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ texto: texto }),
            });

            if (!response.ok) {
                throw new Error('Error del servidor al generar audio.');
            }

            const data = await response.json();

            if (data.status === 'success' && data.audio) {
                this.mostrarMensaje('Reproduciendo...', 'success');
                this.audioPlayer.src = `data:audio/mp3;base64,${data.audio}`;
                this.audioPlayer.play();

                // Manejador para cuando el audio termine
                this.audioPlayer.onended = () => {
                    this.isSpeaking = false;
                    this.mostrarMensaje('Lectura finalizada.', 'info', 1500);
                    // Comprobar si hay más audio en la cola
                    if (this.audioQueue.length > 0) {
                        const siguienteTexto = this.audioQueue.shift();
                        this.leerTexto(siguienteTexto); // Llama a una función interna
                    }
                };
            } else {
                throw new Error(data.error || 'No se recibió audio.');
            }
        } catch (error) {
            console.error('Error en leerTextoSeleccionado:', error);
            this.mostrarMensaje('Error al generar voz.', 'error');
            this.isSpeaking = false;
        }
    }

    // Función interna para manejar la cola
    async leerTexto(texto) {
        if (!texto || this.isSpeaking) return;

        this.isSpeaking = true;
        this.mostrarMensaje('Generando audio...', 'info');
        
        try {
            const response = await fetch('/texto_a_voz', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ texto: texto }),
            });
            const data = await response.json();
            if (data.status === 'success' && data.audio) {
                this.mostrarMensaje('Reproduciendo...', 'success');
                this.audioPlayer.src = `data:audio/mp3;base64,${data.audio}`;
                this.audioPlayer.play();
            } else {
                throw new Error(data.error || 'No se recibió audio.');
            }
        } catch (error) {
            console.error('Error en leerTexto (cola):', error);
            this.mostrarMensaje('Error al generar voz.', 'error');
            this.isSpeaking = false;
        }
    }


    mostrarMensaje(mensaje, tipo = 'info', duracion = 3000) {
        const notif = document.getElementById('accesibilidad-notif');
        if (!notif) return;

        notif.textContent = mensaje;
        notif.className = 'show'; // Quita clases anteriores
        
        if (tipo === 'success') notif.classList.add('success');
        else if (tipo === 'error') notif.classList.add('error');
        
        // Limpiar timeouts anteriores si existen
        if (this.notifTimeout) {
            clearTimeout(this.notifTimeout);
        }

        this.notifTimeout = setTimeout(() => {
            notif.className = '';
        }, duracion);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.lectorPantalla = new LectorPantalla();
});
