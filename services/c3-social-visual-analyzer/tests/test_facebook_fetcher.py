from app.services.facebook_fetcher import _is_media, _unwrap


def test_reaction_gifs_are_not_embedded_urls():
    wrapped = ("https://l.facebook.com/l.php?u=https%3A%2F%2Fmedia.tenor.co%2Fu1Ae1NYGOjEAAAAC%2Ffml-fury.gif"
               "%3Ft%3DAAX6utnHO5sKpMgSCgsTWA&h=AT0")
    assert _is_media(_unwrap(wrapped))
    assert _is_media("https://giphy.com/gifs/abc")
    assert _is_media("https://example.com/a/b/picture.JPG")


def test_real_destinations_are_kept():
    assert not _is_media("https://paypa1-secure.com/login")
    assert not _is_media("https://example.com/downloads/whatsapp-gold.apk")
