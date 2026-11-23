// Gmail add-on: scans the open email with the phishing detector API.
// Privacy: nothing is sent until the user clicks "Scan this email".
const API_URL = "https://d3tlehjrr1ryx6.cloudfront.net";

function onGmailMessageOpen() {
  const button = CardService.newTextButton()
    .setText("Scan this email")
    .setOnClickAction(CardService.newAction().setFunctionName("scanMessage"));
  return card(CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText("The email is sent to the detector only when you click."))
    .addWidget(button));
}

function scanMessage(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);  // access to the open email only
  const message = GmailApp.getMessageById(e.gmail.messageId);
  let result;
  try {
    const response = UrlFetchApp.fetch(API_URL + "/api/scan", {
      method: "post",
      payload: { text: message.getRawContent() },  // same as pasting the email in the web UI
      muteHttpExceptions: true,
    });
    result = response.getResponseCode() === 200
      ? resultCard(JSON.parse(response.getContentText()))
      : errorCard("The API answered with HTTP " + response.getResponseCode() + ".");
  } catch (err) {
    result = errorCard(String(err));
  }
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(result))
    .build();
}

function resultCard(result) {
  const section = CardService.newCardSection().addWidget(
    CardService.newDecoratedText()
      .setTopLabel("Risk")
      .setText("<b>" + result.risk_level + "</b> (score " + result.score + "/100)")
      .setBottomLabel(result.verdict));

  // Findings are sorted by points, so the first 3 are the most important.
  result.findings.slice(0, 3).forEach(function (f) {
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel(f.severity + "  " + (f.points > 0 ? "+" : "") + f.points)
      .setText(escapeHtml(f.title))
      .setBottomLabel(escapeHtml(f.evidence))
      .setWrapText(true));
  });
  if (result.findings.length === 0) {
    section.addWidget(CardService.newTextParagraph().setText("No indicators found."));
  }
  return card(section);
}

function errorCard(text) {
  return card(CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText("Could not scan this email. " + escapeHtml(text))));
}

function card(section) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Phishing check"))
    .addSection(section)
    .build();
}

// Email content is attacker-controlled: never let it be read as card formatting.
function escapeHtml(text) {
  return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
