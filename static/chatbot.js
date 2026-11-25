(() => {
  const widget = document.querySelector(".chatbot");
  const panel = document.querySelector("#chatbot-panel");
  const toggle = document.querySelector(".chatbot-toggle");
  const close = document.querySelector(".chatbot-close");
  const messages = document.querySelector(".chatbot-messages");
  const suggestions = document.querySelector(".chatbot-suggestions");
  const loading = document.querySelector(".chatbot-loading");

  if (!widget || !panel || !toggle || !close || !messages || !suggestions || !loading) return;

  const faqUrl = widget.dataset.faqUrl;
  let faqs = [];
  let version = "";
  let refreshTimer = null;
  let refreshInProgress = false;
  let refreshErrorShown = false;

  const addMessage = (text, sender) => {
    const message = document.createElement("p");
    message.className = `chatbot-message ${sender}`;
    message.textContent = text;
    messages.append(message);
    messages.scrollTop = messages.scrollHeight;
  };

  const renderQuestions = () => {
    suggestions.replaceChildren();
    faqs.forEach((faq) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "chatbot-suggestion";
      button.dataset.faqId = faq.id;
      button.textContent = faq.question;
      suggestions.append(button);
    });
    loading.hidden = true;
  };

  const refreshFaqs = async () => {
    if (refreshInProgress) return;
    refreshInProgress = true;
    try {
      const response = await fetch(faqUrl, { cache: "no-store" });
      if (!response.ok) throw new Error(`FAQ request failed with status ${response.status}`);
      const data = await response.json();
      const validFaqs = Array.isArray(data.faqs)
        && data.faqs.every((item) =>
          typeof item.id === "string"
          && typeof item.question === "string"
          && typeof item.answer === "string"
        );
      if (!validFaqs || typeof data.version !== "string") {
        throw new Error("FAQ response has an invalid format");
      }

      if (data.version !== version) {
        faqs = data.faqs;
        version = data.version;
        renderQuestions();
      }
      refreshErrorShown = false;
    } catch (error) {
      console.error("No se pudieron actualizar las preguntas del chatbot.", error);
      if (!refreshErrorShown) {
        addMessage("No se pudieron cargar las preguntas. Intenta abrir el chat nuevamente más tarde.", "bot");
        refreshErrorShown = true;
      }
    } finally {
      refreshInProgress = false;
    }
  };

  const setOpen = (isOpen) => {
    panel.hidden = !isOpen;
    toggle.setAttribute("aria-expanded", String(isOpen));
    if (isOpen) {
      refreshFaqs();
      if (refreshTimer === null) {
        refreshTimer = window.setInterval(refreshFaqs, 3000);
      }
    } else if (refreshTimer !== null) {
      window.clearInterval(refreshTimer);
      refreshTimer = null;
    }
  };

  toggle.addEventListener("click", () => setOpen(panel.hidden));
  close.addEventListener("click", () => setOpen(false));

  suggestions.addEventListener("click", (event) => {
    const button = event.target.closest(".chatbot-suggestion");
    if (!button) return;
    const faq = faqs.find((item) => item.id === button.dataset.faqId);
    if (!faq) return;
    addMessage(faq.question, "user");
    addMessage(faq.answer, "bot");
  });
})();
