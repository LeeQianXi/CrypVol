//! CrypVol 桌面应用入口。

mod app;
mod appearance;
mod cvk;
mod editor;

fn main() -> iced::Result {
    app::run()
}
