 # Common Stuff
 
XTB in its core works with:
- SAML
- Apache commons

So long out own class these are the main transtive APIs we expose.
In addition we have some not so nice things in here:
- test support is in the main library as we have a circular dependency between test support and tested classes in commons 
  itself along the need to use these classes in other modules. Nothing much so we live with it.

Rules to put classes into common:
- No active spring beans. Use @Bean factories in @Configuration classes where you need them.
- Any library you at as implementation should not cause side-effects on modules depending on common.
