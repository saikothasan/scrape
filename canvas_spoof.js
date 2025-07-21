// Injects a script to slightly modify canvas rendering, a common fingerprinting vector.
// This makes each browser session appear unique to tracking scripts.
;(() => {
  try {
    const getImageData = CanvasRenderingContext2D.prototype.getImageData

    // A function to apply tiny, random noise to the canvas data
    const noisyFunction = (canvas, context) => {
      if (!context) return
      const { width, height } = canvas
      if (width === 0 || height === 0) return

      const imageData = getImageData.call(context, 0, 0, width, height)
      for (let i = 0; i < imageData.data.length; i += 4) {
        // Add a random noise value (-1, 0, or 1) to the alpha channel
        const noise = Math.floor(Math.random() * 3) - 1
        imageData.data[i + 3] = (imageData.data[i + 3] + noise) & 255 // Use bitwise AND to stay within 0-255 range
      }
      context.putImageData(imageData, 0, 0)
    }

    // Override toDataURL
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL
    HTMLCanvasElement.prototype.toDataURL = function () {
      noisyFunction(this, this.getContext("2d"))
      return originalToDataURL.apply(this, arguments)
    }

    // Override toBlob
    const originalToBlob = HTMLCanvasElement.prototype.toBlob
    HTMLCanvasElement.prototype.toBlob = function () {
      noisyFunction(this, this.getContext("2d"))
      return originalToBlob.apply(this, arguments)
    }
  } catch (e) {
    console.error("Error in canvas spoofing script:", e)
  }
})()
