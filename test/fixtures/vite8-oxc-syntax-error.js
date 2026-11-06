
        <!DOCTYPE html>
        <html lang="en">
          <head>
            <meta charset="UTF-8" />
            <title>Error</title>
            <script type="module">
              const error = {"message":"Transform failed with 1 error:\n\n[PARSE_ERROR] Expected `,` or `}` but found `Identifier`\n   ╭─[ src/components/Pay.tsx:2:98 ]\n   │\n 2 │   const broken = { stripeKey: \"__VIBESANE_TEST_STRIPE_KEY__\", msg: \"Olá, senha inválida\" b: 2 };\n   │                  ┬                                                                               ┬  \n   │                  ╰────────────────────────────────────────────────────────────────────────────────── Opened here\n   │                                                                                                  │  \n   │                                                                                                  ╰── `,` or `}` expected\n───╯\n","stack":"    at transformWithOxc (file:///workspace/app/node_modules/vite/dist/node/chunks/node.js:7669:19)\n    at TransformPluginContext.transform (file:///workspace/app/node_modules/vite/dist/node/chunks/node.js:7743:26)\n    at EnvironmentPluginContainer.transform (file:///workspace/app/node_modules/vite/dist/node/chunks/node.js:8632:51)\n    at async loadAndTransform (file:///workspace/app/node_modules/vite/dist/node/chunks/node.js:20108:26)\n    at async viteTransformMiddleware (file:///workspace/app/node_modules/vite/dist/node/chunks/node.js:20328:20)","id":"/workspace/app/src/components/Pay.tsx","frame":"","plugin":"vite:oxc","pluginCode":"export function Pay() {\n  const broken = { stripeKey: \"__VIBESANE_TEST_STRIPE_KEY__\", msg: \"Olá, senha inválida\" b: 2 };\n  return \u003cdiv>{broken.stripeKey}\u003c/div>;\n}\n"}
              try {
                const { ErrorOverlay } = await import("/@vite/client")
                document.body.appendChild(new ErrorOverlay(error))
              } catch {
                const h = (tag, text) => {
                  const el = document.createElement(tag)
                  el.textContent = text
                  return el
                }
                document.body.appendChild(h('h1', 'Internal Server Error'))
                document.body.appendChild(h('h2', error.message))
                document.body.appendChild(h('pre', error.stack))
                document.body.appendChild(h('p', '(Error overlay failed to load)'))
              }
            </script>
          </head>
          <body>
          </body>
        </html>
      