### A failed record no longer resends the rest of its chunk

After Brevo accepted a chunk of events, a failure to record one of them as sent stopped the recording there, and the redelivery sent every later event of the chunk again (up to 199 duplicates). Every event of the chunk is now recorded (each tried 3 times), and only one whose recording still failed is sent again. A dead-letter replay later than the 72 h retention of sent ids still sends its events again (SPEC `brevo/sent-once`).
