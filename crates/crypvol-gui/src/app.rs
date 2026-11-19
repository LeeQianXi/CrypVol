//! 窗口生命周期与编辑会话分发。
use crate::appearance::{Feedback, GAP, action, card, centered, hint};
use crate::{cvk::Document, editor};
use iced::{
    Element, Event, Fill, Subscription, Task,
    keyboard::{self, Key, key::Named},
    widget::{button, column, operation, text},
    window,
};
use std::collections::BTreeMap;

pub fn run() -> iced::Result {
    iced::daemon(App::boot, App::update, App::view)
        .title(|app: &App, id| {
            if let Some(editor) = app.editors.get(&id) {
                editor.title()
            } else if app.prompts.contains_key(&id) {
                "解锁私钥 · CrypVol".to_owned()
            } else {
                "CrypVol".to_owned()
            }
        })
        .subscription(|_| {
            Subscription::batch([
                window::close_requests().map(Message::Close),
                iced::event::listen_with(shortcut),
            ])
        })
        .run()
}

struct App {
    home: window::Id,
    editors: BTreeMap<window::Id, editor::Editor>,
    feedback: Feedback,
    prompts: BTreeMap<window::Id, window::Id>,
}
#[derive(Clone, Debug)]
enum Message {
    New,
    Open,
    Ready(window::Id),
    Edit(window::Id, editor::Message),
    Close(window::Id),
    Focus(bool),
    CancelPrompt(window::Id),
}

impl App {
    fn boot() -> (Self, Task<Message>) {
        let (home, task) = window::open(settings());
        (
            Self {
                home,
                editors: BTreeMap::new(),
                feedback: Feedback::None,
                prompts: BTreeMap::new(),
            },
            task.map(Message::Ready),
        )
    }
    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::New => match Document::new() {
                Ok(document) => return self.open_editor(editor::Editor::new(document)),
                Err(error) => self.feedback = Feedback::Error(error),
            },
            Message::Open => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("CVK", &["cvk"])
                    .pick_file()
                {
                    match editor::Editor::load(path) {
                        Ok(editor) => return self.open_editor(editor),
                        Err(error) => self.feedback = Feedback::Error(error),
                    }
                }
            }
            Message::Edit(id, message) => {
                if let Some(editor) = self.editors.get_mut(&id) {
                    let unlocking = message.is_unlock();
                    editor.update(message);
                    let prompt = self
                        .prompts
                        .iter()
                        .find_map(|(prompt, owner)| (*owner == id).then_some(*prompt));
                    if editor.needs_password() && prompt.is_none() {
                        let (prompt, task) = window::open(window::Settings {
                            size: iced::Size::new(460.0, 320.0),
                            min_size: None,
                            resizable: false,
                            ..settings()
                        });
                        self.prompts.insert(prompt, id);
                        return task.map(Message::Ready);
                    }
                    if unlocking && let Some(id) = editor.focus_id() {
                        return operation::focus(id);
                    }
                    if !editor.needs_password()
                        && let Some(prompt) = prompt
                    {
                        self.prompts.remove(&prompt);
                        return window::close(prompt);
                    }
                }
            }
            Message::Close(id) => {
                if let Some(owner) = self.prompts.remove(&id) {
                    if let Some(editor) = self.editors.get_mut(&owner) {
                        editor.update(editor::Message::CancelUnlock);
                    }
                    return window::close(id);
                }
                if id == self.home {
                    if self.editors.values().any(|editor| !editor.confirm_close()) {
                        return Task::none();
                    }
                    return iced::exit();
                }
                if self
                    .editors
                    .get(&id)
                    .is_some_and(|editor| !editor.confirm_close())
                {
                    return Task::none();
                }
                self.editors.remove(&id);
                let prompts: Vec<_> = self
                    .prompts
                    .iter()
                    .filter_map(|(prompt, owner)| (*owner == id).then_some(*prompt))
                    .collect();
                let mut tasks = vec![window::close(id)];
                for prompt in prompts {
                    self.prompts.remove(&prompt);
                    tasks.push(window::close(prompt));
                }
                return Task::batch(tasks);
            }
            Message::CancelPrompt(id) => {
                if self.prompts.contains_key(&id) {
                    return self.update(Message::Close(id));
                }
            }
            Message::Ready(id) => {
                let owner = self.prompts.get(&id).copied().unwrap_or(id);
                if let Some(input) = self.editors.get(&owner).and_then(editor::Editor::focus_id) {
                    return operation::focus(input);
                }
            }
            Message::Focus(previous) => {
                return if previous {
                    operation::focus_previous()
                } else {
                    operation::focus_next()
                };
            }
        }
        Task::none()
    }
    fn open_editor(&mut self, editor: editor::Editor) -> Task<Message> {
        self.feedback = Feedback::None;
        let (id, task) = window::open(settings());
        self.editors.insert(id, editor);
        task.map(Message::Ready)
    }
    fn view(&self, id: window::Id) -> Element<'_, Message> {
        if let Some(owner) = self.prompts.get(&id)
            && let Some(editor) = self.editors.get(owner)
        {
            let owner = *owner;
            return editor
                .password_view()
                .map(move |message| Message::Edit(owner, message));
        }
        if let Some(editor) = self.editors.get(&id) {
            return editor.view().map(move |message| Message::Edit(id, message));
        }
        centered(
            card(
                column![
                    column![text("CrypVol").size(36), hint("密钥管理")].spacing(8),
                    action("打开密钥…").width(Fill).on_press(Message::Open),
                    action("新建密钥")
                        .style(button::secondary)
                        .width(Fill)
                        .on_press(Message::New),
                    self.feedback.view(),
                ]
                .spacing(GAP),
            )
            .width(Fill)
            .max_width(460),
        )
    }
}
fn settings() -> window::Settings {
    window::Settings {
        size: iced::Size::new(860.0, 720.0),
        min_size: Some(iced::Size::new(560.0, 440.0)),
        position: window::Position::Centered,
        exit_on_close_request: false,
        ..Default::default()
    }
}

fn shortcut(event: Event, status: iced::event::Status, id: window::Id) -> Option<Message> {
    let Event::Keyboard(keyboard::Event::KeyPressed {
        key,
        modifiers,
        repeat: false,
        ..
    }) = event
    else {
        return None;
    };
    if key == Key::Named(Named::Tab) && status == iced::event::Status::Ignored {
        return Some(Message::Focus(modifiers.shift()));
    }
    if key == Key::Named(Named::Escape) {
        // 只有密码提示窗口处理取消，普通编辑窗口交由关闭确认流程。
        return Some(Message::CancelPrompt(id));
    }
    if modifiers.command()
        && let Key::Character(value) = key
    {
        return match value.as_str() {
            "s" | "S" => Some(Message::Edit(
                id,
                if modifiers.shift() {
                    editor::Message::SaveAs
                } else {
                    editor::Message::Save
                },
            )),
            "o" | "O" => Some(Message::Open),
            "n" | "N" => Some(Message::New),
            _ => None,
        };
    }
    None
}
