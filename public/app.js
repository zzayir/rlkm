const sign_in_btn = document.querySelector("#sign-in-btn");
const sign_up_btn = document.querySelector("#sign-up-btn");
const container = document.querySelector(".container");

sign_up_btn.addEventListener('click', () =>{
    container.classList.add("sign-up-mode");
});

sign_in_btn.addEventListener('click', () =>{
    container.classList.remove("sign-up-mode");
});
// Wait for the DOM to fully load
document.addEventListener("DOMContentLoaded", () => {
    // Apply fade-in animation to the entire body content at once
    gsap.from("body", {
        opacity: 0,
        duration: 1.5,
        ease: "power2.out"
    });
});




