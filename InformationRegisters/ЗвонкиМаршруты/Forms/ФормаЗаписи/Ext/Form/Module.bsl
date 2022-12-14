&НаСервере
Процедура ПриСозданииНаСервере(Отказ,СтандартнаяОбработка)

// Получим сведения о звонке, которому принадлежит текущая строка маршрута
//-------------------------------------------------------------------------------------------------
	Звонок = РегистрыСведений.Звонки.СоздатьМенеджерЗаписи();
	Звонок.Сигнатура = СокрЛП(Запись.Сигнатура);
	Звонок.Прочитать();

	Если (Звонок.Выбран() = Ложь) Тогда
		Отказ = Истина;
		Возврат;
	КонецЕсли;

// Сформируем заголовок формы
//-------------------------------------------------------------------------------------------------
	Темп = ?(Звонок.Принят,"Принятый ","Непринятый ");
	Темп = Темп + ?(Звонок.ЭтоВходящий,"входящий ","исходящий ");
	Темп = Темп + ". Внешний номер: " + СокрЛП(Звонок.АбонентВнешний);
	ЭтаФорма.Заголовок = СокрЛП(Темп);
	ЭтаФорма.ТолькоПросмотр = Истина;

// Сформируем представление события
//-------------------------------------------------------------------------------------------------
	Темп = СокрЛП(Запись.КодСобытия) + ": " + СокрЛП(Запись.ИмяСобытия);
	Элементы.НадписьСобытие.Заголовок = СокрЛП(Темп);

// Сведения об операторе события
//-------------------------------------------------------------------------------------------------
	Доступно = ЗначениеЗаполнено(Запись.Оператор);
	Элементы.Приемник.Видимость = Доступно;

	Если (Доступно = Истина) Тогда
		Если (ТипЗнч(Запись.Оператор) = Тип("СправочникСсылка.ТелОчереди")) Тогда
			ЭтаФорма.Приемник = "Очередь " + СокрЛП(Запись.Оператор) + " - ";
			ЭтаФорма.Приемник = ЭтаФорма.Приемник + СокрЛП(Запись.Оператор.Назначение);
		Иначе
			ВладСсылка = Телефония.ВладелецПолучить(Запись.Оператор);
			ЭтаФорма.Приемник = СокрЛП(Запись.Оператор) + " (владелец не найден)";
			Элементы.Приемник.Гиперссылка = Истина;

			Если (ЗначениеЗаполнено(ВладСсылка)) Тогда
				ЭтаФорма.Приемник = СокрЛП(ВладСсылка.ТочкаРазмещения);
				ЭтаФорма.Приемник = ЭтаФорма.Приемник + " / " + СокрЛП(ВладСсылка.Наименование);
				ЭтаФорма.Приемник = ЭтаФорма.Приемник + " / " + СокрЛП(Запись.Оператор);
			КонецЕсли;
		КонецЕсли;
	КонецЕсли;
КонецПроцедуры

//-------------------------------------------------------------------------------------------------

&НаКлиенте
Процедура ПриемникНажатие(Элемент,СтандартнаяОбработка)

// Получим ссылку на владельца внутреннего телефона
//-------------------------------------------------------------------------------------------------
	ВладСсылка = Телефония.ВладелецПолучить(Запись.Оператор);
	ОткрываемоеЗначение = ?(ЗначениеЗаполнено(ВладСсылка),ВладСсылка,Запись.Оператор);
	ОткрытьЗначение(ОткрываемоеЗначение);
	СтандартнаяОбработка = Ложь;
КонецПроцедуры

&НаКлиенте
Процедура СигнатураОткрытие(Элемент,СтандартнаяОбработка)

// Откроем форму звонка по выбранной Сигнатуре
//-------------------------------------------------------------------------------------------------
	Попытка
		СтрКлюча = Новый Структура("Сигнатура",СокрЛП(Запись.Сигнатура));
		КлючЗаписи = ЗначенияСервера.ПолучитьКлючЗаписи("Звонки",СтрКлюча);
		ОткрытьЗначение(КлючЗаписи);
	Исключение
	КонецПопытки;

	СтандартнаяОбработка = Ложь;
КонецПроцедуры
