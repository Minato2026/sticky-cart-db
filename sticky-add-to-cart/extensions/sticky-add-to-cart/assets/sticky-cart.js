document.addEventListener("DOMContentLoaded", function () {
    console.log("Sticky Cart Embed Loaded ✅");
    const btn = document.getElementById("sticky-add-to-cart");

    if (!btn) return;

    btn.addEventListener("click", function () {
        const form = document.querySelector('form[action*="/cart/add"]');
        if (form) {
            form.submit();
        } else {
            console.warn("No Add to Cart form found!");
        }
    });
});
